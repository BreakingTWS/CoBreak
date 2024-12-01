require "mkmf"

#Welcome to CoBreak ExtConf

abort "Missing library crypto" unless have_library("crypto")
#if not have_header("openssl/ssl.h") and have_header("nettle/nettle-types.h") and have_library("crypto")
#  abort("missing libreries of openssl / nettle / crypto")
#end
if (`gem search sqlite3 --installed` == "true\n")
  #dir of configuration
  dir_config("cobreak")
#  if have_header("cobreak_ruby.h")
#    have_header("string.h")
#    if RUBY_PLATFORM =~ /mswin|darwin/
#      have_header("window.h")
#    end
    create_header
    have_library('stdc++');
    have_library('gcrypt');
    have_header("ruby.h")
    have_header("openssl/hmac.h")
    have_header("openssl/evp.h")
    $CFLAGS << " -Wall -O3"

    create_makefile("cobreak/cobreak")
 # else
 #   abort("missing header's of CoBreak")
#  end
else
  abort("missing libreries, use (gem install sqlite3)")
end
