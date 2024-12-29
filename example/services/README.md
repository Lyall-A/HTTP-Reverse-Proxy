_defaults.json is a special file that is used as a base for all other services
so anything not specified on other files will use values from the default service
properties that appear on both the service value will be used and take preference over defaults.

Any file prefixed with _ will be ignored and not loaded. With the exception of _defaults.json whith is special.

Files can me added, removed and modified on the fly they will take effect live. Existing connections might still be using old settings, but it will take effect for any new incomming connections.