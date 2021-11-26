using System;
using System.Data.SqlTypes;
using System.Diagnostics;
using Microsoft.SqlServer.Server;

public class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]

    public static void cmdExec(SqlString execCommand)
    {
        // We create new process with cmd.exe and pass our input as argumnet
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = String.Format(@" /C {0}", execCommand);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // Then to read data from the cmd output we need to create the record to get data from the Pipe

        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();

        proc.WaitForExit();
        proc.Close();


    }
}
