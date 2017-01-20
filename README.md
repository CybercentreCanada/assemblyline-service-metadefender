# MetaDefender Service

This Assemblyline services interfaces with [Metadefender Core](https://www.opswat.com/metadefender-core) multi-scanning AV engine.

**NOTE**: This service **requires you to buy** any licence. It also **requires you to install** Metadefender Core on a seperate machine/VM. It is **not** preinstalled during a default installation

## Execution

The service use Metadefender Core API to send the file to the server for analysis and report the results back to the user for all AV engines installed on the server.

## Installation of Metadefender Core

To install Metadefender Core you can follow our detailled documentation [here](mdcore_install/install_notes.md).

## Updates

This service support auto-update in both online and offline environment. This is configurable in the service config.

## Licensing

The service was developed with Metadefender Core 4.x.

Contact your Metadefender Core reseller to get access to the proper licence you need for your deployment: [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)