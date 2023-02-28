# php_server_mapper
Win32 PE server mapper written on PHP.
<br><br>
## System requirements:
- Win32 PE to load (dll, sys)
- PHP 5.0+-
- Web Server (nginx/apache)
<br><br>
## Features:
- Complete premapper, no unnecessary data is sent to client
- Optimized PE parser
- API set fix
- Themida and Code Virtualizer support
- Win32 PE support
- Reloc table is being stripped
- Doesn't require VDS to run (only webhosting is required)
- Popular data serialization used - (json)
- No POST or PUT requests (very good for optimization and times to load)
- Can be easily integrated with xenforo or any other web engine written on php
- Requires LITERALLY any version of php
- Project includes client written on C++
- Even ordinal imports can be resolved (untested)
<br><br>
## Improvements:
- Add caching system to store the bin after initialization (not required)
<br><br>
## Credits:
- [@es3n1n](https://github.com/es3n1n)
- [@violanes](https://github.com/violanes)
- Mr. Nursultan Probirkeen (contact: og@mail.ru)
- [@cpz](https://github.com/cpz)
