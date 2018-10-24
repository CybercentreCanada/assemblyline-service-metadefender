# MetaDefender Service

This Assemblyline service interfaces with the [MetaDefender Core](https://www.opswat.com/metadefender-core) multi-scanning AV engine.

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** MetaDefender Core on a seperate machine/VM. It is **not** preinstalled during a default installation.

## Overview

The MetaDefender service uses the MetaDefender Core API to send files to the server for scanning using more than 30 AV engines. The results from each of the installed AV engines are retrieved and displayed to the user. This service supports the use of multiple MetaDefender deployments in environments where large file loads are expected.

## Installing and Configuring MetaDefender Core

**NOTE**: This service was developed with **MetaDefender Core v4**.

To install and activate Metadefender Core, you can follow the instructions [here](https://onlinehelp.opswat.com/corev4/2.2._Installing_Metadefender.html). You can have multiple MetaDefender deployments if your environment expects large file loads.

Once MetaDefender has been installed and activated with your license, the following settings are recommended to improve the file scanning rate:

* Turning off the following engines under **Inventory > Technologies**
	* Data sanitization engine 
	* Archive engine
* Frequently cleaning up the scan database using both of the following methods:  
	* Setting all the data retention options to the lowest time value under **Settings > Data Retention**
	* Using a scheduled task on your MetaDefender server, see [here](mdcore_install/install_notes.md) for instructions

## Service Options

* **BASE\_URL** - [default: *http://localhost:8008/*] The URL(s) of the MetaDefender deployment(s)
* **MD\_TIMEOUT** - [default: *40 secs*] Maximum amount of time to wait while connecting to the MetaDefender server
* **MAX\_MD\_SCAN_TIME** - [default: *3 secs*] Maximum amount of time to wait for scan results before the MetaDefender server is put on a brief timeout (only applicable when multiple MetaDefender deployments are used)

## Updates

This service supports auto-update in both online and offline environments. This is configurable in the service config.

## Licensing

Contact your MetaDefender Core reseller to get access to the licence you need for your deployment: [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)
