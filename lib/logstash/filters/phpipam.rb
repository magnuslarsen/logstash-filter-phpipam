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
  config :auth, validate: :boolean, default: true

  # Whether to use caching or not
  config :cache, validate: :boolean, default: true

  # Which file to use as cache storage. Should be placed on a tmpfs volume for maximum performance
  config :cache_path, validate: :string, default: '/tmp/logstash-filter-phpipam.json'

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

    # Get data from cache or phpIPAM if not in cache
    event_data = search_cache(ip)
    event_data = phpipam_data(ip, event) if event_data.is_a?(FalseClass)

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
    target = "[#{target}]" if target !~ %r{^\[[^\[\]]+\]$}
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

  # Checks if the value is defined and not nil or error
  # @param value: a value to check
  # @return [bool]
  def okay?(value)
    !defined?(value).nil? && !value.nil? && value['error'].nil?
  end

  # Queries phpIPAM and formats the data
  # @param ip: an IP-address to query
  # @return [hash]
  def phpipam_data(ip, event)
    # Fetch base data needed from phpIPAM
    ip_data = send_rest_request('GET', "api/#{@app_id}/addresses/search/#{ip}/")

    # If the IP wasn't found, return and do nuthin'
    if !ip_data['error'].nil? && ip_data['error']
      event.tag('_phpipam_ip_not_found')
      return { 'error' => true }
    end

    subnet_data = send_rest_request('GET', "api/#{@app_id}/subnets/#{ip_data['subnetId']}/") unless nil_or_empty?(ip_data['subnetId'])
    vlan_data   = send_rest_request('GET', "api/#{@app_id}/vlans/#{subnet_data['vlanId']}/") unless nil_or_empty?(subnet_data['vlanId'])

    device_data   = send_rest_request('GET', "api/#{@app_id}/tools/devices/#{ip_data['deviceId']}/") unless ip_data['deviceId'] == '0' || nil_or_empty?(ip_data['deviceId'])
    location_data = send_rest_request('GET', "api/#{@app_id}/tools/locations/#{ip_data['location']}/") unless ip_data['location'] == '0' || nil_or_empty?(ip_data['location'])

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
    if okay?(subnet_data)
      base['subnet']               = {}
      base['subnet']['id']         = ip_data['subnetId'].to_i
      base['subnet']['section_id'] = subnet_data['sectionId'].to_i
      base['subnet']['bitmask']    = subnet_data['calculation']['Subnet bitmask'].to_i
      base['subnet']['wildcard']   = subnet_data['calculation']['Subnet wildcard']
      base['subnet']['netmask']    = subnet_data['calculation']['Subnet netmask']
      base['subnet']['network']    = subnet_data['calculation']['Network']
    end

    # VLAN information
    if okay?(vlan_data)
      base['vlan']                = {}
      base['vlan']['id']          = subnet_data['vlanId'].to_i
      base['vlan']['number']      = vlan_data['number'].to_i unless nil_or_empty?(vlan_data['number'])
      base['vlan']['name']        = vlan_data['name'] unless nil_or_empty?(vlan_data['name'])
      base['vlan']['description'] = vlan_data['description'] unless nil_or_empty?(vlan_data['description'])
    end

    # Device information
    if okay?(device_data)
      type = send_rest_request('GET', "api/#{@app_id}/tools/device_types/#{device_data['type']}/")

      base['device']                = {}
      base['device']['id']          = ip_data['deviceId'].to_i
      base['device']['name']        = device_data['hostname'] unless nil_or_empty?(device_data['hostname'])
      base['device']['description'] = device_data['description'] unless nil_or_empty?(device_data['description'])
      base['device']['type']        = type['tname'] unless nil_or_empty?(type['tname'])

      # If the IP doesn't have the location directly, use the one from the device (if that has one)
      unless okay?(location_data)
        location_data = send_rest_request('GET', "api/#{@app_id}/tools/locations/#{device_data['location']}/") unless device_data['location'] == '0' || nil_or_empty?(device_data['location'])
      end
    end

    # Location information
    if okay?(location_data)
      base['location']                = {}
      base['location']['id']          = ip_data['location'].to_i
      base['location']['address']     = location_data['address'] unless nil_or_empty?(location_data['address'])
      base['location']['name']        = location_data['name'] unless nil_or_empty?(location_data['name'])
      base['location']['description'] = location_data['description'] unless nil_or_empty?(location_data['description'])
      base['location']['location']    = { 'lat' => location_data['lat'], 'lon' => location_data['long'] } unless nil_or_empty?(location_data['lat'])
    end

    # Cache it for future needs
    cache_data(base)

    # all your base are belong to us
    base
  end

  # Caches data (if possible)
  # @param data: the data to cache
  # @return [void]
  def cache_data(data)
    data = data.to_json

    File.open(@cache_path, 'a') do |file|
      file.write(data + "\n")
      @logger.debug? && @logger.debug('Cached data', data: data)
    rescue StandardError
      @logger.debug? && @logger.debug('Cache file is not writable, skipping caching of data', data: data, cache_file: @cache_path)
      break
    end
  end

  # Seaches the cache file for the IP.
  # Returns a hash if the IP was found, else false
  # @param ip: The IP-address to search for
  # @return [hash/bool]
  def search_cache(ip)
    @logger.debug? && @logger.debug('Searching cache...', ip: ip)

    return false unless File.exist?(@cache_path)

    File.foreach(@cache_path) do |line|
      line = JSON.parse(line)
      return line if line['ip']['address'] == ip
    end

    false
  end
end
