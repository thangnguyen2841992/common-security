# Local service recovery and IntelliJ classpath

`Cannot load driver class: org.mariadb.jdbc.Driver` means the launched JVM lacks MariaDB Connector/J. The service POMs and executable JARs contain that dependency, but a stale IntelliJ Maven model can still launch the old MySQL classpath.

To synchronize the IDE:

1. Stop failed application run/debug configurations.
2. Open the Maven tool window in IntelliJ and choose **Reload All Maven Projects**.
3. In External Libraries, verify `org.mariadb.jdbc:mariadb-java-client` appears: version 3.5.7 for oauth2 and 3.5.8 for staff/nihongo-user with the current POMs.
4. Build the project and launch the service again.

The new drivers have already been downloaded to this computer's Maven repository. Do not switch the driver setting back to MySQL merely to match the IDE's stale classpath.

As a separate local recovery option, run the verified executable JARs from the workspace root:

```powershell
./common-security/scripts/start-local-services.ps1
```

This starts auth (8081), staff (8085), and nihongo-user (8086) in the background, checks that each JAR contains the JDBC dependency, skips already-listening ports, and uses `ddl-auto=validate` so this recovery launch does not change the database schema. Logs and the launched PIDs are recorded under `.local/startup-check`. Database credentials are loaded from the existing configuration and are not printed.

Do not start an IDE instance on the same service port while its JAR process is running. Use the recorded PID to stop only the corresponding JAR process before switching back to IDE debugging. The script leaves existing processes alone.
