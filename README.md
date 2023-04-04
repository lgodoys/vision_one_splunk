# Vision_One_for_Splunk
The Vision One for Splunk Add-on adds compatibility for usage of multiple XDR tokens into single Splunk instance

RELEASE NOTES:

Version 1.0.2: Apr 04, 2023
Added support to multiple XDR endpoints, removing hardcoded XDR endpoint and added new field XDR Endpoint in additional parameters.
Modified captions below username and password fields in account, to add information about usage of these fields in app.
Thanks to Chris for his recommendations

Version 1.0.1: Mar 15, 2023
Updates Trend Micro XDR API from legacy version in Official XDR Add-on to API v3. Updates the _time field extraction for each input and sourcetype, updates sourcetypes to use json extraction, and correct some minor bugs.

Version 1.0.0: Mar. 09, 2023
App created. 
Solves incompatibility of Trend Micro Vision One for Splunk (XDR) app with multiple Vision One consoles, adding support for multiple API Tokens. Exclusive usage for Vision One API, because the Endpoint URL is fixed in code.
Includes all original inputs, only few changes in original code of inputs to add support to multiple consoles.
This apps isn't related with Trend Micro team, it is developed to solve incompatibility in some cases where some companies has multiple VO consoles for multiple tenants or to allow Cybersec companies that hosts multiple clients and their VO consoles in Splunk Enterprise.
