# logstash-filter-phpipam
A Logstash filter that looks up an IP-address, and returns results from phpIPAM

## Installation
### Prerequisites
[Redis](https://redis.io/) is required for this plugin to work.

You can install it using most your distributions package manager.

#### Ubuntu example
You can install it with apt:
```bash
sudo apt install redis
```


### Plugin
This plugin can be installed using the `logstash-plugin` command in $LOGSTASH_HOME:
```bash
${LOGSTASH_HOME:-/usr/share/logstash}/bin/logstash-plugin install logstash-filter-phpipam
```

## Redis configuration
Redis is primarily used as a [LRU cache](https://redis.io/topics/lru-cache), and can be configured in a lot of ways.

The two highly recommended settings to set, are `maxmemory` and `maxmemory-policy`:
* `maxmemory` can be tested using the `redis-cli --lru-test` [command](https://redis.io/topics/rediscli#performing-an-lru-simulation)
* `maxmemory-policy` I would set to `allkeys-lru`

The above settings would limit the memory that Redis can use. The limit should be high enough to contain almost all keys. \
If the limit is reached--and `maxmemory-policy` is set to `allkeys-lru`--the least accessed keys would be evicted first.

Every key will also have an expiration time of `cache_fresshness` (default 24 hours) associated, meaning that every key will live for 24 hours maximum. \
This is to prevent cached data to become stale, and always keep (approximately) up-to-date data from phpIPAM.

With my production data, every 50 keys is about 1 MiB of memory.

## Configuration options
| Option            | Type    | Default       | Comment                                                                          |
| ----------------- | ------- | ------------- | -------------------------------------------------------------------------------- |
| host              | string  |               | What host to connect to with protocol and optional port (e.g. https://fqdn:3000) |
| app_id            | string  |               | See below                                                                        |
| username          | string  |               | Username to use for the connection                                               |
| password          | string  |               | Password to use for the connection                                               |
| auth              | boolean | true          | Whether to use authentication or not                                             |
| cache_ip          | integer | 0             | ID of the redis database for IP-addresses                                        |
| cache_subnet      | integer | 1             | ID of the redis database for subnets                                             |
| cache_vlan        | integer | 2             | ID of the redis database for vlans                                               |
| cache_device      | integer | 3             | ID of the redis database for devices                                             |
| cache_location    | integer | 4             | ID of the redis database for locations                                           |
| cache_device_type | integer | 5             | ID of the redis database for device types                                        |
| cache_freshness   | integer | 86400 (1 day) | How long, in seconds, a value should be cached before it's expired               |
| source            | string  |               | Which field the IP-address is in                                                 |
| target            | string  | phpipam       | Where to place the phpIPAM data in                                               |

`app_id` can be found in phpIPAM: Administration -> API \
It's recommended to use SSL when accessing the app_id in phpIPAM.

## Geo-points
By default the lon and lat are mapped as normal floats, NOT geo-points!

To use the latitude and longtitude in Kibana Maps, you either need to:
1. Preload mappings yourself
2. Use preloaded mappings from something like Filebeat (7.0+)

For option 2, if you use the default target of `phpipam`, you can do something like this, after the phpipam filter:
```
mutate {
  rename => {
    "[phpipam][location][location]" => "[geo][location]"
  }
}
```

## Example
This example...
```ruby
phpipam {
  host     => "https://phpipam.local.domain"
  app_id   => "logstash"
  username => "username"
  password => "password"
  source   => "[source][ip]"
  target   => "[source][phpipam]"
}
```
...would produce:
```ruby
"source" => {
  "phpipam" => {
    "subnet" => {
      "network"    => "172.16.1.0",
      "bitmask"    => 24,
      "netmask"    => "255.255.255.0",
      "section_id" => 1,
      "wildcard"   => "0.0.0.255",
      "id"         => 1
    },
    "ip" => {
      "description" => "This is my test IP",
      "hostname"    => "test.domain.local",
      "id"          => 1,
      "note"        => "This switch is in test!",
      "address"     => "172.16.1.10",
      "mac"         => "aa:bb:cc:dd:ee:ff"
      "owner"       => "Testing Team"
    },
    "vlan" => {
      "name"      => "TestVLAN",
      "number"    => 100,
      "id"        => 1,
      "domain_id" => 1,
    },
    "device" => {
      "name"        => "test.domain.local",
      "description" => "Juniper Switch",
      "type"        => "Switch",
      "id"          => 1
    },
    "location" => {
      "name"     => "Null Island",
      "id"       => 1,
      "location" => {
        "lat" => 0.0,
        "lon" => 0.0
      },
      "address" => "Null Island, Atlantic Ocean"
    }
  }
}
```
Provided that all that information is entered in phpIPAM.

Empty values in phpIPAM will not be pulled, therefore the output can vary, depending on the information gathered from the IP-address.
