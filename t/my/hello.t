use strict;
use warnings FATAL => 'all';
use t::APISIX 'no_plan';

no_long_string();
no_root_location();
no_shuffle();

add_block_preprocessor(sub {
    my ($block) = @_;

    if (!$block->request) {
        $block->set_value("request", "GET /apisix/admin/routes");
    }

    if (!$block->no_error_log && !$block->error_log) {
        $block->set_value("no_error_log", "[error]\n[alert]");
    }
});
run_tests;
__DATA__

=== TEST 1: configure plugins in the consumer and run its rewrite phase

--- timeout: 15

--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/consumers/jack',
                 ngx.HTTP_PUT,
                [[{
                    "username": "jack",
                    "plugins": {
                        "key-auth": {
                            "key": "auth-jack"
                        }
                    }
                }]]
                )
            if code >= 300 then
                ngx.say(body)
                return
            end

            local code, body = t('/apisix/admin/routes/1',
                 ngx.HTTP_PUT,
                 [[{
                        "plugins": {
                            "key-auth": {},
                            "proxy-rewrite": {
                               "headers": {
                                   "add": {
                                      "xtest": "123"
                                    }
                               }
                            },
                            "serverless-post-function": {
                              "functions": [
                                "return function(conf, ctx) \n ngx.log(ngx.WARN,'router') \n ngx.say(ngx.req.get_headers().xtest); \n end"
                                ]
                            }
                        },
                        "upstream": {
                            "nodes": {
                                "127.0.0.1:1980": 1
                            },
                            "type": "roundrobin"
                        },
                        "uri": "/hello"
                }]]
                )

            if code >= 300 then
                ngx.status = code
            end

        }
    }
--- request
GET /t
--- response_body
passed



=== TEST 2: hit routes
--- timeout: 15
--- request
GET /hello
--- more_headers
apikey: auth-jack
--- response_body
123123
