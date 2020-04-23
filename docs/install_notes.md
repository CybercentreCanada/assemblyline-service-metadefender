# MetaDefender Core - Database Cleanup 

**NOTE**: The following instructions are for **MetaDefender Core v4** running on a **Windows** machine.

If your deployment experiences a heavy file load, MetaDefender tends to become slower over time due to the increasing size of its database. In order to overcome this issue, a task can be scheduled to run a PowerShell script ([metacleanup.ps1](metacleanup.ps1)) which will temporarily stop the MetaDefender service, delete the database and then restart the service. Every time the script runs, there is a down time of approximately 30-90 secs during which the MetaDefender service is unreachable. If you have multiple deployments of MetaDefender, you can offset the scheduled task for each deployment to minimize service downtime.

## Set-up Instructions

1. Download the [metacleanup.ps1](metacleanup.ps1) script on your machine and place it in a location such as ``C:\scripts\``
2. Open the **Task Scheduler** program
3. In the **Actions** pane on the right, click **Create Task...**
4. The **Create Task** window will open
5. In the **General** tab:
	* Enter a name for the task
	* Select the **Run whether user is logged on or not** option
	* Select the **Run with highest privileges** option
6. Go to the **Triggers** tab and click **New...** 
7. In the **New Trigger** window that opens:
	* Choose to begin the task **On a schedule**
	* Select the **Daily** option
	* Set the start date and time to a value in the future (to ensure the task is triggered)
	* Set the task to recur every **1 day**
	* Select the option to repeat the task every **15 minutes** for a duration of **1 day**
	* Ensure the **Enabled** option is selected to enable to trigger
	* Click **OK** when done
8. Go to the **Actions** tab and click **New...**
9. In the **New Action** window that opens:
	* Select the action type to **Start a program**
	* In the **Program/script** field, enter ``powershell.exe``
	* In the **Add arguments** field, enter ``-ExecutionPolicy Bypass C:\scripts\metacleanup.ps1``
	* Click **OK** when done
10. Go to the **Conditions** tab and ensure that all options are unselected
11. Click **OK** to save the scheduled task

The MetaDefender database cleanup task has now been scheduled and should run every 15 minutes. 