# Metadefender Core 4.x - Install notes

If your cluster see heavy load and metadefender becomes slower and slower, you'll have to install our metacleanup.ps1 script as a schedule task every hour. Essentially the problem is that the metadefender DB cannot keep up with all the scan so we shutdown the metadefender service, remove the DB and restart the service.

We are working with Opswat to fix the issue.