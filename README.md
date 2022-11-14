# MetaDefender Service

This Assemblyline service interfaces with the [MetaDefender Core](https://www.opswat.com/metadefender-core) multi-scanning AV engine.

**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** MetaDefender Core on a seperate machine/VM. It is **not** preinstalled during a default installation.

## Overview

The MetaDefender service uses the MetaDefender Core API to send files to the MetaDefender Core server that you set-up to scan files for malware using upto 30 leading antivirus engines (depending on your license). The scan results from each of the installed antivirus engines are retrieved and displayed to the user. This service supports the use of multiple MetaDefender Core deployments for environments with heavy file loads.

## Licensing

Contact your MetaDefender Core reseller to get access to the licence you need for your deployment: [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)

## Installing MetaDefender Core

**NOTE**: The following instructions are for **MetaDefender Core v4** running on a **Windows** machine.

1. Download the MetaDefender Core v4 installation package from the [OPSWAT Portal](https://portal.opswat.com/) 
2. Install MetaDefender Core v4 by following the instructions on the install wizard
3. Open a web browser and go to ``http://localhost:8008``
4. Complete the basic configuration wizard to activate MetaDefender Core

## Configuring MetaDefender Core

Once MetaDefender Core has been installed and activated with your license, the following configurations are recommended to improve the file scanning rate:

* Using RAMDISK for the _tempdirectory_, see [here](https://onlinehelp.opswat.com/corev4/2.6._Special_installation_options.html) for instructions
* Turning off the following engines under **Inventory > Technologies**
	* Data sanitization engine 
	* Archive engine
* Frequently cleaning up the scan database using both of the following methods:
	* Setting all the data retention options to the lowest time value under **Settings > Data Retention**
	* Updating your MetaDefender Core version so that PostgreSQL is the default database

## Service Options

* **api_key**: API Key used to connect to the MetaDefender API
* **base_url**: The URL(s) of the MetaDefender deployment(s)
	* If you have a **single** MetaDefender Core deployment, set the service variable to **str** type and enter the URL of your MetaDefender Core deployment
	* If you have **multiple** MetaDefender Core deployments, set the service variable to **list** type and enter the URLs of your MetaDefender Core deployments separated by a comma
* **verify_certificate**: Setting to False will ignore verifying the SSL certificate
* **md_version**: Version of MetaDefender you're connecting to (3 or 4)
* **md_timeout**: Maximum amount of time to wait while connecting to the MetaDefender server
* **max_md_scan_time**: Maximum amount of time to wait for scan results before the MetaDefender server is put on a brief timeout (only applicable when multiple MetaDefender deployments are used)
* **av_config**: Dictionary containing details that we will use for revising or omitting antivirus signature hits
  * **blocklist**: A list of antivirus vendors who we want to omit from all results
  * **kw_score_revision_map**: A dictionary where the keys are the keywords that could be found in signatures, and the value is the revised score
  * **sig_score_revision_map**: A dictionary where the keys are the signatures that you want to revise, and the values are the scores that the signatures will be revised to

## Updating Antivirus Definitions

Most of the antivirus vendors release definition updates at least once per day. Many release multiple daily. Some vendors release updates on weekends while others do not. Based on your type of deployment, you can select the frequency at which updates are applied.

### Online Deployment of MetaDefender Core

If your MetaDefender Core is deployed in an online environment, you can set the update options by going to **Settings > Updates Settings**. You can also manually initiate an update by going to **Inventory > Technologies** and then clicking **UPDATE ALL**.

### Offline Deployment of MetaDefender Core

If your MetaDefender Core is deployed in an offline environment, you will need to use the Update Downloader utility to download the antivirus definition updates in an online environment and then transfer the updates manually to the offline environment. See [here](https://onlinehelp.opswat.com/downloader/) for instructions on how to use the Update Downloader utility. Once the definition updates have been downloaded and transferred to the offline deployment, you can have MetaDefender monitor a local directory for any new definition updates added to it. You can set which local folder MetaDefender monitors by going to **Settings > Update Settings** then selecting **FOLDER** as the source for updates and then setting the **Pick up updates from** field to your local updates directory.