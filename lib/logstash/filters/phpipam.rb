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

  # Application id of the API application (administration -> myfirstapi)
  config :app_id, validate: :string, required: true

  # Username and password to use for the connection
  config :username, validate: :string, required: true
  config :password, validate: :password, required: true

  # IP-address field to look up
  config :source, validate: :string, required: true

  # Target field to place all values
  config :target, validate: :string, default: 'phpipam'

  def register
    # Get a session token
    @token = send_rest_request('POST', "api/#{@app_id}/user/", true)['token']
  end

  def filter(event)
    value = event.get(@source)

    valid_ip?(value)

    # Get data from phpIPAM
    event_data = phpipam_data(value)

    return if event_data.emtpy?

    # Set the data to the target path
    event.set(@target, event_data)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end

  # Validates a IP-address. Always returns true. Breaks if a non-valid IP was parsed
  # @param ip: an IP-address
  # @return [bool]
  def valid_ip?(ip)
    IPAddr.new(ip)

    # Return true. Rescue would take over if a non-valid IP was parsed
    true
  rescue StandardError
    raise LogStash::ConfigurationError, I18n.t(
      'logstash.runner.configuration.invalid_plugin_register',
      plugin: 'filter',
      type:   'phpipam',
      error:  'Could not validate IP-address',
    )
  end

  # Sends a GET method REST request.
  # @param method: which HTTP method to use (DELETE, PATCH, POST, GET)
  # @param url_path: path to connect to
  # @param basic_auth: whether to use basic_auth or not
  # @return [hash]
  def send_rest_request(method, url_path, basic_auth = false)
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
    request.basic_auth(@username, @password) if basic_auth

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

    # Parse and return the body
    return JSON.parse(response.body)['data'] if response.is_a?(Net::HTTPSuccess)

    # Else return an error object
    { 'error' => true }
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
    # Fetch all the data needed from phpIPAM
    ip_data       = send_rest_request('GET', "api/#{@app_id}/addresses/search/#{ip}/")
    subnet_data   = send_rest_request('GET', "api/#{@app_id}/subnets/#{ip_data['subnetId']}/") unless nil_or_empty?(ip_data['subnetId'])
    vlan_data     = send_rest_request('GET', "api/#{@app_id}/vlans/#{subnet_data['vlanId']}/") unless nil_or_empty?(subnet_data['vlanId'])

    # If the IP wasn't found, return nothing, and exit
    return {} if !ip_data['error'].nil? && ip_data['error']

    # Base hash to format data in
    base = {
      'ip'     => {},
      'subnet' => {},
      'vlan'   => {},
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
    base['subnet']['id']         = ip_data['subnetId'].to_i
    base['subnet']['section_id'] = subnet_data['sectionId'].to_i
    base['subnet']['bitmask']    = subnet_data['calculation']['Subnet bitmask']
    base['subnet']['wildcard']   = subnet_data['calculation']['Subnet wildcard']
    base['subnet']['netmask']    = subnet_data['calculation']['Subnet netmask']

    # VLAN information
    base['vlan']['id']          = subnet_data['vlanId'].to_i
    base['vlan']['number']      = vlan_data['number'].to_i unless nil_or_empty?(vlan_data['number'])
    base['vlan']['name']        = vlan_data['name'] unless nil_or_empty?(vlan_data['name'])
    base['vlan']['description'] = vlan_data['description'] unless nil_or_empty?(vlan_data['description'])

    # all your base are belong to us
    base
  end
end
