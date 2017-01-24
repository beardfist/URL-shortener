# short.beardfist.com
A URL shortener written in Flask with the following features
 - Validates URLs before accepting them.
 - Makes sure the URL can be resolved.
 - Doesn't allow schemas like data://
 - Uses Web of Trust API to verify that the URL doesn't contain illegal or malicious content.
 - Reverse lookup of existing URLs.
 - Keeps track of number of hits per URL.
 - Ensures url is always as short as possible. Starts at 'a' and moves up through a-Z 0-9 and then to 'aa'
 - Simple bootstrap design with easy-to-modify colors via provided style.css

A live version can be found at http://short.beardfist.com
