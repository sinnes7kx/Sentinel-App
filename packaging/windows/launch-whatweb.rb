# Run from the packaged plugin directory and connect directly to the scoped site.
%w[http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY].each { |name| ENV.delete(name) }
Dir.chdir(File.join(__dir__, 'whatweb'))
$0 = File.expand_path('whatweb')
load $0
