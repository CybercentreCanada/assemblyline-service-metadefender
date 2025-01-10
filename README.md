[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_metadefender-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-metadefender)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-metadefender)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-metadefender)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-metadefender)](./LICENSE)
# MetaDefender Service

This Assemblyline service interfaces with the [MetaDefender Core](https://www.opswat.com/metadefender-core) multi-scanning AV engine.

## Service Details
**NOTE**: This service **requires you to buy** a licence. It also **requires you to install** MetaDefender Core on a seperate machine/VM. It is **not** preinstalled during a default installation.

### Overview

The MetaDefender service uses the MetaDefender Core API to send files to the MetaDefender Core server that you set-up to scan files for malware using upto 30 leading antivirus engines (depending on your license). The scan results from each of the installed antivirus engines are retrieved and displayed to the user. This service supports the use of multiple MetaDefender Core deployments for environments with heavy file loads.

### Licensing

Contact your MetaDefender Core reseller to get access to the licence you need for your deployment: [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)

### Installing MetaDefender Core

**NOTE**: The following instructions are for **MetaDefender Core v4** running on a **Windows** machine.

1. Download the MetaDefender Core v4 installation package from the [OPSWAT Portal](https://portal.opswat.com/)
2. Install MetaDefender Core v4 by following the instructions on the install wizard
3. Open a web browser and go to ``http://localhost:8008``
4. Complete the basic configuration wizard to activate MetaDefender Core

### Configuring MetaDefender Core

Once MetaDefender Core has been installed and activated with your license, the following configurations are recommended to improve the file scanning rate:

* Using RAMDISK for the _tempdirectory_, see [here](https://onlinehelp.opswat.com/corev4/2.6._Special_installation_options.html) for instructions
* Turning off the following engines under **Inventory > Technologies**
	* Data sanitization engine
	* Archive engine
* Frequently cleaning up the scan database using both of the following methods:
	* Setting all the data retention options to the lowest time value under **Settings > Data Retention**
	* Updating your MetaDefender Core version so that PostgreSQL is the default database

### Service Options

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

### Updating Antivirus Definitions

Most of the antivirus vendors release definition updates at least once per day. Many release multiple daily. Some vendors release updates on weekends while others do not. Based on your type of deployment, you can select the frequency at which updates are applied.

#### Online Deployment of MetaDefender Core

If your MetaDefender Core is deployed in an online environment, you can set the update options by going to **Settings > Updates Settings**. You can also manually initiate an update by going to **Inventory > Technologies** and then clicking **UPDATE ALL**.

#### Offline Deployment of MetaDefender Core

If your MetaDefender Core is deployed in an offline environment, you will need to use the Update Downloader utility to download the antivirus definition updates in an online environment and then transfer the updates manually to the offline environment. See [here](https://onlinehelp.opswat.com/downloader/) for instructions on how to use the Update Downloader utility. Once the definition updates have been downloaded and transferred to the offline deployment, you can have MetaDefender monitor a local directory for any new definition updates added to it. You can set which local folder MetaDefender monitors by going to **Settings > Update Settings** then selecting **FOLDER** as the source for updates and then setting the **Pick up updates from** field to your local updates directory.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name MetaDefender \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-metadefender

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service MetaDefender

Ce service Assemblyline s'interface avec le moteur AV à balayage multiple de [MetaDefender Core] (https://www.opswat.com/metadefender-core).

## Détails du service
**NOTE** : Ce service **nécessite l'achat** d'une licence. Il **exige également que vous installiez** MetaDefender Core sur une machine/VM séparée. Il n'est **pas** préinstallé lors d'une installation par défaut.

### Vue d'ensemble

Le service MetaDefender utilise l'API de MetaDefender Core pour envoyer des fichiers au serveur MetaDefender Core que vous avez configuré pour analyser les fichiers à la recherche de malwares en utilisant jusqu'à 30 moteurs antivirus de premier plan (en fonction de votre licence). Les résultats de l'analyse de chacun des moteurs antivirus installés sont récupérés et affichés à l'utilisateur. Ce service prend en charge l'utilisation de plusieurs déploiements de MetaDefender Core pour les environnements avec de lourdes charges de fichiers.

### Licences

Contactez votre revendeur MetaDefender Core pour obtenir la licence dont vous avez besoin pour votre déploiement : [https://www.opswat.com/partners/channel-partners#find-a-partner](https://www.opswat.com/partners/channel-partners#find-a-partner)

### Installation de MetaDefender Core

**REMARQUE** : Les instructions suivantes concernent **MetaDefender Core v4** fonctionnant sur une machine **Windows**.

1. Téléchargez le paquet d'installation de MetaDefender Core v4 à partir du [Portail OPSWAT] (https://portal.opswat.com/).
2. Installez MetaDefender Core v4 en suivant les instructions de l'assistant d'installation.
3. Ouvrez un navigateur web et allez sur `http://localhost:8008``.
4. Complétez l'assistant de configuration de base pour activer MetaDefender Core.

### Configurer MetaDefender Core

Une fois que MetaDefender Core a été installé et activé avec votre licence, les configurations suivantes sont recommandées pour améliorer le taux d'analyse des fichiers :

* Utilisation de RAMDISK pour le répertoire _tempdirectory_, voir [ici] (https://onlinehelp.opswat.com/corev4/2.6._Special_installation_options.html) pour les instructions.
* Désactiver les moteurs suivants sous **Inventaire > Technologies**
	* Moteur d'assainissement des données
	* Moteur d'archivage
* Nettoyer fréquemment la base de données d'analyse en utilisant les deux méthodes suivantes :
	* Régler toutes les options de rétention des données à la valeur la plus basse sous **Paramètres > Rétention des données**.
	* Mise à jour de la version de MetaDefender Core pour que PostgreSQL soit la base de données par défaut.

### Options de service

**api_key** : Clé API utilisée pour se connecter à l'API de MetaDefender
* **base_url** : L'URL du (des) déploiement(s) de MetaDefender
	* Si vous avez un **seul** déploiement de MetaDefender Core, réglez la variable de service sur le type **str** et entrez l'URL de votre déploiement de MetaDefender Core.
	* Si vous avez **plusieurs** déploiements de MetaDefender Core, définissez la variable de service comme étant de type **list** et entrez les URL de vos déploiements de MetaDefender Core en les séparant par une virgule.
**verify_certificate** : La valeur False ignore la vérification du certificat SSL.
**md_version** : Version de MetaDefender à laquelle vous vous connectez (3 ou 4)
**md_timeout** : Temps d'attente maximum lors de la connexion au serveur MetaDefender.
**max_md_scan_time** : Durée maximale d'attente des résultats de l'analyse avant que le serveur MetaDefender ne soit mis en attente (uniquement applicable lorsque plusieurs déploiements de MetaDefender sont utilisés).
**av_config** : Dictionnaire contenant les détails que nous utiliserons pour réviser ou omettre les signatures antivirus.
  **blocklist** : Une liste d'éditeurs d'antivirus que nous voulons exclure de tous les résultats.
  **kw_score_revision_map** : Un dictionnaire dont les clés sont les mots-clés qui pourraient être trouvés dans les signatures, et la valeur est le score révisé.
  * **sig_score_revision_map** : Un dictionnaire dont les clés sont les signatures que vous souhaitez réviser et les valeurs sont les scores auxquels les signatures seront révisées.

### Mise à jour des définitions d'antivirus

La plupart des éditeurs d'antivirus publient des mises à jour de définitions au moins une fois par jour. Nombre d'entre eux le font plusieurs fois par jour. Certains éditeurs publient des mises à jour le week-end, d'autres non. En fonction de votre type de déploiement, vous pouvez sélectionner la fréquence à laquelle les mises à jour sont appliquées.

#### Déploiement en ligne de MetaDefender Core

Si votre MetaDefender Core est déployé dans un environnement en ligne, vous pouvez définir les options de mise à jour en allant dans **Paramètres > Paramètres des mises à jour**. Vous pouvez également lancer manuellement une mise à jour en allant dans **Inventaire > Technologies** puis en cliquant sur **MISE A JOUR TOUTES**.

#### Déploiement hors ligne de MetaDefender Core

Si votre MetaDefender Core est déployé dans un environnement hors ligne, vous devrez utiliser l'utilitaire Update Downloader pour télécharger les mises à jour des définitions de l'antivirus dans un environnement en ligne, puis transférer manuellement les mises à jour dans l'environnement hors ligne. Voir [ici] (https://onlinehelp.opswat.com/downloader/) pour savoir comment utiliser l'utilitaire Update Downloader. Une fois que les mises à jour des définitions ont été téléchargées et transférées vers le déploiement hors ligne, vous pouvez demander à MetaDefender de surveiller un répertoire local pour détecter toute nouvelle mise à jour de définition qui y serait ajoutée. Vous pouvez définir le dossier local que MetaDefender surveille en allant dans **Paramètres > Paramètres de mise à jour**, en sélectionnant **DOSSIER** comme source des mises à jour et en définissant le champ **Recueillir les mises à jour à partir de** sur votre répertoire de mises à jour local.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name MetaDefender \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-metadefender

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
