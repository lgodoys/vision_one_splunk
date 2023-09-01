RELEASE NOTES:

Version 1.0.5: Sep 01, 2023
Solved an issue that allows to run requests in HTTP and HTTPS endpoints, being not complain with Splunk Cloud Guidelines. Was added to requests helper method a check to allow only HTTPS endpoints.

Version 1.0.4: May 25, 2023
Solved an issue related with OAT input, that updates constantly the Risk Level, changing between Risk Levels from XDR API Endpoint and local level.

Version 1.0.3: May 02, 2023
Modified support for multiple XDR endpoints, removing Additional parameters and added dropdown to select specific endpoint for account based on API token. XDR endpoints are listed in <https://automation.trendmicro.com/xdr/Guides/Regional-Domains>.

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
