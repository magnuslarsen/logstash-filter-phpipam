# frozen_string_literal: true

require 'logstash/filters/base'

require 'ipaddr'
require 'json'
require 'net/http'
require 'openssl'
require 'uri'

# A Logstash filter that looks up an IP-address, and returns results from phpIPAM
class LogStash::Filters::Phpipam < LogStash::Filters::Base
  config_name 'phpipam'

  # Full host path to connect to, e.g. 'https://phpipam.domain.local:3000'
  config :host, validate: :string, required: true

  # Application id of the API application (Administration -> API)
  config :app_id, validate: :string, required: true

  # Username and password to use for the connection
  config :username, validate: :string, default: ''
  config :password, validate: :string, default: ''

  # Whether to use authentication or not
  config :auth, validate: :boolean, required: true, default: true

  # IP-address field to look up
  config :source, validate: :string, required: true

  # Target field to place all values
  config :target, validate: :string, default: 'phpipam'

  def register
    # Validate auth
    raise LogStash::ConfigurationError, 'Authentication was enabled, but no user/pass found' if @auth && (@username.empty? || @password.empty?)

    # Get a session token
    @token = send_rest_request('POST', "api/#{@app_id}/user/")['token'] if @auth

    @target = normalize_target(@target)
  end

  def filter(event)
    ip = event.get(@source)

    return unless valid_ip?(ip, event)

    # Get data from phpIPAM
    event_data = phpipam_data(ip)

    return if !event_data['error'].nil? && event_data['error']

    # Set the data to the target path
    event.set(@target, event_data)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end

  # make sure @target is in the format [field name] if defined,
  # i.e. not empty and surrounded by brakets
  # @param target: the target to normalize
  # @return [string]
  def normalize_target(target)
    target = "[#{target}]" if target && target !~ %r{^\[[^\[\]]+\]$}
    target
  end

  # Validates a IP-address
  # @param ip: an IP-address
  # @param event: The Logstash event variable
  # @return [bool]
  def valid_ip?(ip, event)
    IPAddr.new(ip)

    @logger.debug? && @logger.debug('Valid IP', ip: ip)

    # Return true. Rescue would take over if a non-valid IP was parsed
    true
  rescue StandardError
    @logger.debug? && @logger.debug('NOT a valid IP', ip: ip)
    event.tag('_phpipam_invalid_ip')
    false
  end

  # Sends a GET method REST request.
  # @param method: which HTTP method to use (POST, GET)
  # @param url_path: path to connect to
  # @param basic_auth: whether to use basic_auth or not
  # @return [hash]
  def send_rest_request(method, url_path)
    @logger.debug? && @logger.debug('Sending request', host: @host, path: url_path)

    url = URI("#{@host}/#{url_path}")

    http             = Net::HTTP.new(url.host, url.port)
    http.use_ssl     = url.scheme == 'https'
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    request = case method
              when 'POST' then Net::HTTP::Post.new(url)
              when 'GET' then Net::HTTP::Get.new(url)
              end

    request['accept']        = 'application/json'
    request['content-type']  = 'application/json'
    request['phpipam-token'] = @token unless @token.nil?
    request.basic_auth(@username, @password) if @token.nil? && @auth

    begin
      response = http.request(request)
    rescue StandardError
      raise LogStash::ConfigurationError, I18n.t(
        'logstash.runner.configuration.invalid_plugin_register',
        plugin: 'filter',
        type:   'phpipam',
        error:  'Could not connect to configured host',
      )
    end

    # Parse the body
    rsp = JSON.parse(response.body)

    # Raise an error if not a code 200 is returned
    raise LogStash::ConfigurationError, "#{rsp['code']}:#{rsp['message']}" if rsp['code'] != 200

    # Return error if no data field is present, else return the data
    rsp = if rsp['data'].nil?
            { 'error' => true }
          else
            rsp['data'].is_a?(Array) ? rsp['data'][0] : rsp['data']
          end

    @logger.debug? && @logger.debug('Got response', body: response.body, data: rsp)
    rsp
  end

  # Checks whether the value is nil or empty
  # @param value: a value to check
  # @return [bool]
  def nil_or_empty?(value)
    value.nil? || value.empty?
  end

  # Queries phpIPAM and formats the data
  # @param ip: an IP-address to query
  # @return [hash]
  def phpipam_data(ip)
    # Fetch base data needed from phpIPAM
    ip_data = send_rest_request('GET', "api/#{@app_id}/addresses/search/#{ip}/")

    # If the IP wasn't found, return and do nuthin'
    return { 'error' => true } if !ip_data['error'].nil? && ip_data['error']

    subnet_data = send_rest_request('GET', "api/#{@app_id}/subnets/#{ip_data['subnetId']}/") unless nil_or_empty?(ip_data['subnetId'])
    vlan_data   = send_rest_request('GET', "api/#{@app_id}/vlans/#{subnet_data['vlanId']}/") unless nil_or_empty?(subnet_data['vlanId'])

    # Base hash to format data in
    base = {
      'ip' => {},
    }

    # IP information
    base['ip']['id']          = ip_data['id'].to_i
    base['ip']['address']     = ip_data['ip']
    base['ip']['description'] = ip_data['description'] unless nil_or_empty?(ip_data['description'])
    base['ip']['hostname']    = ip_data['hostname'] unless nil_or_empty?(ip_data['hostname'])
    base['ip']['mac']         = ip_data['mac'] unless nil_or_empty?(ip_data['mac'])
    base['ip']['note']        = ip_data['note'] unless nil_or_empty?(ip_data['note'])
    base['ip']['owner']       = ip_data['owner'] unless nil_or_empty?(ip_data['owner'])

    # Subnet information
    if !defined?(subnet_data).nil? && subnet_data['error'].nil?
      base['subnet']               = {}
      base['subnet']['id']         = ip_data['subnetId'].to_i
      base['subnet']['section_id'] = subnet_data['sectionId'].to_i
      base['subnet']['bitmask']    = subnet_data['calculation']['Subnet bitmask'].to_i
      base['subnet']['wildcard']   = subnet_data['calculation']['Subnet wildcard']
      base['subnet']['netmask']    = subnet_data['calculation']['Subnet netmask']
    end

    # VLAN information
    if !defined?(vlan_data).nil? && vlan_data['error'].nil?
      base['vlan']                = {}
      base['vlan']['id']          = subnet_data['vlanId'].to_i
      base['vlan']['number']      = vlan_data['number'].to_i unless nil_or_empty?(vlan_data['number'])
      base['vlan']['name']        = vlan_data['name'] unless nil_or_empty?(vlan_data['name'])
      base['vlan']['description'] = vlan_data['description'] unless nil_or_empty?(vlan_data['description'])
    end

    # all your base are belong to us
    base
  end
end
