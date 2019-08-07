# logstash-filter-phpipam
A Logstash filter that looks up an IP-address, and returns results from phpIPAM

## Installation
This plugin can be installed using the `logstash-plugin` command in $LOGSTASH_HOME:
```bash
${LOGSTASH_HOME}/bin/logstash-plugin install logstash-filter-phpipam
```

## Configuration options
| Option     | Type    | Default                           | Comment                                                                         |
| ---------- | ------- | --------------------------------- | ------------------------------------------------------------------------------- |
| host       | string  |                                   | What host to connect to with protocol and optional port(e.g. https://fqdn:3000) |
| app_id     | string  |                                   | See below                                                                       |
| username   | string  |                                   | Username to use for the connection                                              |
| password   | string  |                                   | Password to use for the connection                                              |
| auth       | boolean | true                              | Whether to use authentication or not                                            |
| cache      | boolean | true                              | Whether to use a cache file or not                                              |
| cache_path | string  | /tmp/logstash-filter-phpipam.json | Where to place the cache file. tmpfs is recommended                             |
| source     | string  |                                   | Which field the IP-address is in                                                |
| target     | string  | phpipam                           | Where to place the phpIPAM data in                                              |

`app_id` can be found in phpIPAM: Administration -> API \
It's recommended to use SSL when accessing the app_id in phpIPAM.

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
    },
    "vlan" => {
      "name"   => "TestVLAN",
      "number" => 100,
      "id"     => 1
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
        "lat" => "0.000000",
        "lon" => "0.000000"
      },
      "address" => "Null Island, Atlantic Ocean"
    }
  }
}
```
Provided that all that information is entered in phpIPAM.

Empty values in phpIPAM will not be pulled, therefore the output can vary, depending on the information gathered from the IP-address.