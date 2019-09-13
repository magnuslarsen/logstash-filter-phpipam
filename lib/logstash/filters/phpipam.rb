# frozen_string_literal: true

require 'logstash/filters/base'

require 'ipaddr'
require 'json'
require 'net/http'
require 'openssl'
require 'uri'
require 'redis'

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

  # Cache fressness
  config :cache_freshness, validate: :number, default: 86_400

  # All the caching stores
  config :cache_ip, validate: :number, default: 0
  config :cache_subnet, validate: :number, default: 1
  config :cache_vlan, validate: :number, default: 2
  config :cache_device, validate: :number, default: 3
  config :cache_location, validate: :number, default: 4
  config :cache_device_types, validate: :number, default: 5

  # IP-address field to look up
  config :source, validate: :string, required: true

  # Target field to place all values
  config :target, validate: :string, default: 'phpipam'

  def register
    # Validate auth
    raise LogStash::ConfigurationError, 'Authentication was enabled, but no user/pass found' if @auth && (@username.empty? || @password.empty?)

    # Get a session token
    @token = send_rest_request('POST', "api/#{@app_id}/user/")['token'] if @auth

    # Normalize target
    @target = normalize_target(@target)

    @cache_freshness = @cache_freshness.to_i

    @cs_ip           = Redis.new(db: @cache_ip, id: 'logstash-filter-phpipam')
    @cs_subnet       = Redis.new(db: @cache_subnet, id: 'logstash-filter-phpipam')
    @cs_vlan         = Redis.new(db: @cache_vlan, id: 'logstash-filter-phpipam')
    @cs_device       = Redis.new(db: @cache_device, id: 'logstash-filter-phpipam')
    @cs_location     = Redis.new(db: @cache_location, id: 'logstash-filter-phpipam')
    @cs_device_types = Redis.new(db: @cache_device_types, id: 'logstash-filter-phpipam')

    # Validate Redis connection
    begin
      @cs_ip.ping
    rescue Redis::CannotConnectError
      raise Redis::CannotConnectError, 'Cannot connect to Redis!'
    end
  end

  def close
    @logger.debug? && @logger.debug('Persisting databases...')

    # Persist the database to disk, when the pipeline ends
    @cs_ip.bgsave # Will persist all databases
  end

  def filter(event)
    ip = event.get(@source)

    return if ip.nil?

    return unless valid_ip?(ip, event)

    # Get the data
    event_data = phpipam_data(ip)

    # Tag and return if no IP was found
    if event_data.nil?
      event.tag('_phpipam_ip_not_found')
      return
    end

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

  # Validates an IP-address
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

  # Sends a GET method REST request. Returns nil if no data/an error was found
  # @param method: which HTTP method to use (POST, GET)
  # @param url_path: path to connect to
  # @return [hash/nil]
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

    # Return nil if no data field is present, else return the data
    rsp = if rsp['data'].nil?
            nil
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

  # Get phpIPAM data either from cache or phpIPAM.
  # If data was found from phpIPAM, it will cache it for future needs.
  # If the data wasn't found in either cache or phpIPAM, nil is returned.
  # @param ip - IP-address to lookup
  # @return [hash/nil]
  def phpipam_data(ip)
    # Base hash to format data in
    base = {
      'ip'       => {},
      'subnet'   => {},
      'vlan'     => {},
      'device'   => {},
      'location' => {},
    }

    # If 0 is returned, it has been cached as non-existent
    return nil if @cs_ip.get(ip) == '0'

    ## IP LOOKUP ##
    if @cs_ip.get(ip).nil?
      ip_data = send_rest_request('GET', "api/#{@app_id}/addresses/search/#{ip}/")

      # Return and cache 0 for this IP, if it wasn't found in phpIPAM
      if ip_data.nil?
        @cs_ip.set(ip, '0', ex: @cache_freshness)
        return nil
      end

      # IP information
      base['ip']['id']          = ip_data['id'].to_i
      base['ip']['address']     = ip_data['ip']
      base['ip']['description'] = ip_data['description'] unless nil_or_empty?(ip_data['description'])
      base['ip']['hostname']    = ip_data['hostname'] unless nil_or_empty?(ip_data['hostname'])
      base['ip']['mac']         = ip_data['mac'] unless nil_or_empty?(ip_data['mac'])
      base['ip']['note']        = ip_data['note'] unless nil_or_empty?(ip_data['note'])
      base['ip']['owner']       = ip_data['owner'] unless nil_or_empty?(ip_data['owner'])

      # Get all the ID's
      base['ip']['subnet_id']   = ip_data['subnetId'].to_i
      base['ip']['device_id']   = ip_data['deviceId'].to_i
      base['ip']['location_id'] = ip_data['location'].to_i

      @cs_ip.set(ip, base['ip'].to_json, ex: @cache_freshness)
    else
      base['ip'] = JSON.parse(@cs_ip.get(ip))
    end

    ## SUBNET LOOKUP ##
    subnet_id = base['ip']['subnet_id']

    # If 0 is returned, it doesn't exist. Only lookup if a nonzero value is returned
    if subnet_id.positive?
      if @cs_subnet.get(subnet_id).nil?
        subnet_data = send_rest_request('GET', "api/#{@app_id}/subnets/#{subnet_id}/")

        # Subnet data
        base['subnet']['id']         = subnet_id
        base['subnet']['section_id'] = subnet_data['sectionId'].to_i
        base['subnet']['bitmask']    = subnet_data['calculation']['Subnet bitmask'].to_i
        base['subnet']['wildcard']   = subnet_data['calculation']['Subnet wildcard']
        base['subnet']['netmask']    = subnet_data['calculation']['Subnet netmask']
        base['subnet']['network']    = subnet_data['calculation']['Network']

        # Get VLAN id and location _id
        base['subnet']['vlan_id']     = subnet_data['vlanId'].to_i
        base['subnet']['location_id'] = subnet_data['location'].to_i

        @cs_subnet.set(subnet_id, base['subnet'].to_json, ex: @cache_freshness)
      else
        base['subnet'] = JSON.parse(@cs_subnet.get(subnet_id))
      end
    end

    ## VLAN LOOKUP ##
    vlan_id = base['subnet']['vlan_id']

    # If 0 is returned, it doesn't exist. Only lookup if a nonzero value is returned
    if vlan_id.positive?
      if @cs_vlan.get(vlan_id).nil?
        vlan_data = send_rest_request('GET', "api/#{@app_id}/vlans/#{vlan_id}/")

        # VLAN data
        base['vlan']['id']          = vlan_id
        base['vlan']['domain_id']   = vlan_data['domainId'].to_i
        base['vlan']['number']      = vlan_data['number'].to_i unless nil_or_empty?(vlan_data['number'])
        base['vlan']['name']        = vlan_data['name'] unless nil_or_empty?(vlan_data['name'])
        base['vlan']['description'] = vlan_data['description'] unless nil_or_empty?(vlan_data['description'])

        @cs_vlan.set(vlan_id, base['vlan'].to_json, ex: @cache_freshness)
      else
        base['vlan'] = JSON.parse(@cs_vlan.get(vlan_id))
      end
    end

    ## DEVICE LOOKUP ##
    device_id = base['ip']['device_id']

    # If 0 is returned, it doesn't exist. Only lookup if a nonzero value is returned
    if device_id.positive?
      if @cs_device.get(device_id).nil?
        device_data = send_rest_request('GET', "api/#{@app_id}/tools/devices/#{device_id}/")
        type_id     = device_data['type']

        # Device type_name is another REST call
        if @cs_device_types.get(type_id).nil?
          type_name = send_rest_request('GET', "api/#{@app_id}/tools/device_types/#{type_id}/")['tname']

          @cs_device_types.set(type_id, type_name, ex: @cache_freshness)
        else
          type_name = @cs_device_types.get(type_id)
        end

        base['device']['id']          = device_id
        base['device']['name']        = device_data['hostname'] unless nil_or_empty?(device_data['hostname'])
        base['device']['description'] = device_data['description'] unless nil_or_empty?(device_data['description'])
        base['device']['type']        = type_name

        # Get device location
        base['device']['location_id'] = device_data['location'].to_i

        @cs_device.set(device_id, base['device'].to_json, ex: @cache_freshness)
      else
        base['device'] = JSON.parse(@cs_device.get(device_id))
      end
    end

    ## LOCATION LOOKUP ##
    # Get the first positive location_id from the list
    location_id = [base['ip']['location_id'], base['device']['location_id'], base['subnet']['location_id']].select { |num|
      !num.nil? && num.positive?
    }[0] || 0

    # If 0 is returned, it doesn't exist. Only lookup if a nonzero value is returned
    if location_id.positive?
      if @cs_location.get(location_id).nil?
        location_data = send_rest_request('GET', "api/#{@app_id}/tools/locations/#{location_id}/")

        # Location  data
        base['location']['id']          = location_id
        base['location']['address']     = location_data['address'] unless nil_or_empty?(location_data['address'])
        base['location']['name']        = location_data['name'] unless nil_or_empty?(location_data['name'])
        base['location']['description'] = location_data['description'] unless nil_or_empty?(location_data['description'])
        base['location']['location']    = { 'lat' => location_data['lat'].to_f, 'lon' => location_data['long'].to_f } unless nil_or_empty?(location_data['lat'])

        @cs_location.set(location_id, base['location'].to_json, ex: @cache_freshness)
      else
        base['location'] = JSON.parse(@cs_location.get(location_id))
      end
    end

    # Clean-up keys that aren't needed in the final Logstash output
    base['ip'].delete('subnet_id')
    base['ip'].delete('device_id')
    base['ip'].delete('location_id')
    base['subnet'].delete('vlan_id')
    base['subnet'].delete('location_id')
    base['device'].delete('location_id')
    base.delete_if { |_, val| val.empty? }

    # all your base are belong to us
    base

  # Crash hard incase the connection to Redis stops
  rescue Redis::CannotConnectError
    raise Redis::CannotConnectError, 'Lost connection to Redis!'
  end
end
