using System;
using System.IO;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;


namespace Atp
{

    class Program 
    {

        static void Main(string[] args)
        {
            try
            {
                Runspace runspace = RunspaceFactory.CreateRunspace();

                // open it

                runspace.Open();

                // create a pipeline and feed it the script text

                Pipeline pipeline = runspace.CreatePipeline();
                String xyz = File.ReadAllText("covid" +".txt");
                pipeline.Commands.AddScript(xyz);
   
                pipeline.Commands.Add("out-default");

                pipeline.Invoke();

                //test poc poc poc 

                runspace.Close();

            }
            catch (Exception e)
            {
            }
        }

   
    }



}
