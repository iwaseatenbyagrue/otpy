otpy
=====

otpy is a simple command-line OTP token generator.

It can produce both TOTP and HOTP tokens, making it able to replace e.g. Google Authenticator.

The code is currently minimal (essentially implementing core OTP functions and little else).

Usage
-------

A TOTP token can be produced given a suitable secret:

```
> otpy totp testinginginging
549890

```

And HOTP can be produced given a token and count:

```

> otpy hotp -c 1 testinginginging
823363

```

Roadmap
---------

It would be useful to add some form of token/counter database, notably to avoid leaving secrets in .*_history files. 

Ideally, this would be a protected database similar to those of various password managers.

The Password Safe v3 format (http://keybox.rubyforge.org/password-safe-db-format.html) seems a reasonable choice.
The code for that, and its integration with otpy, remain to be done.


License
--------

Copyright (C) 2017 iwaseatenbyagrue

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/. 
