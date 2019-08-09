# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name          = 'logstash-filter-phpipam'
  s.version       = '0.7.4'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'A Logstash filter that returns results from phpIPAM'
  s.description   = 'A Logstash filter that looks up an IP-address, and returns results from phpIPAM'
  s.homepage      = 'https://github.com/magnuslarsen/logstash-filter-phpipam'
  s.authors       = ['magnuslarsen']
  s.email         = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*', 'spec/**/*', 'vendor/**/*', '*.gemspec', '*.md', 'CONTRIBUTORS', 'Gemfile', 'LICENSE', 'NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { 'logstash_plugin' => 'true', 'logstash_group' => 'filter' }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', '~> 2.0'
  s.add_development_dependency 'logstash-devutils'
end
