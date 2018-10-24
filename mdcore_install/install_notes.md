# Metadefender Core 4.x - Install notes

If your cluster experiences a heavy load and Metadefender becomes slower and slower, you'll have to install our [metacleanup.ps1](../mdcore_install/install_notes.md) script as a scheduled task to every 15-60 mins, depending on the load. Essentially the problem is that the Metadefender DB cannot keep up with all the scan requests so we shutdown the Metadefender service, remove the DB and restart the service. Every time the script is run, there is a down time of approximately 30-90 secs. If multiple clusters of Metadefender are used, the script run schedule for each cluster can be offset from each other to minimize service downtime.

We are working with Opswat to fix the issue.
