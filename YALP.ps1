
$Source = @" 
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;

namespace faster
{
    public class Q
    { 
        public EventLogReader Qlocal(string Path, string Query)
        {
            var q = Query;
            var EQ = new EventLogQuery(Path, PathType.FilePath, q);
            try
            {
                var Reader = new EventLogReader(EQ);
                return Reader;
            }
            catch (EventLogNotFoundException)
            {
                Console.WriteLine("Error while reading the event logs!");
                var lost = new EventLogReader("");
                return lost;
            }
        }

        public IEnumerable<int> UID(EventLogReader log)                                     //Distinct Event IDs in a log
        {
            var EvtIDs = new List<int>();
            for (EventRecord eInst = log.ReadEvent(); null != eInst; eInst = log.ReadEvent())
            {
                EvtIDs.Add(eInst.Id);
            }
            IEnumerable<int> distinctIDs = EvtIDs.Distinct();
            return distinctIDs;
        }

        public ICollection<string> PullX(string Path, int ID)                               //Snag XML Blob
        {
            var q = "*[System/EventID=" + ID.ToString() + "]";
            var set = Qlocal(Path, q);
            ICollection<string> setX = new List<string>();
            for (EventRecord ev = set.ReadEvent(); null != ev; ev = set.ReadEvent())
            { setX.Add(ev.ToXml()); }
            return setX;
        }

        public void proof(string path, ICollection<string> Xmls, string code, string d)     //Muti-Threaded High Level Parse
        {        
            ConcurrentBag<string> Final = new ConcurrentBag<string>();
            var head = Xmls.ElementAt(0);
            string source = path.Substring(0, path.Length - 5) + "_" + code + ".csv";
            string dataH = "\"";

            IDictionary<string, string> HEAD = Q.Parse(head);
            foreach (string f in HEAD.Keys) { dataH += f + "\"" + d + "\""; }
            dataH = dataH.Substring(0, dataH.Length - 2);

            int k = 0;
            Parallel.ForEach(Xmls, (currentfile) =>
           {
                IDictionary<string, string> FINALLY = Q.Parse(currentfile);
                string data = "\"";
                foreach (string f in FINALLY.Values) { data += f + "\"" + d + "\""; }
                data = data.Replace("  "," ");
                data = data.Replace("\t", "");
                data = data.Replace("\r", "");
                data = data.Replace("\n", "_");
                data = data.Substring(0, data.Length - 2);
                Final.Add(data);
                k++;
            });
            //path += source + "_" + code + ".csv";
            List<string> hope = Final.ToList();
            var old = hope[0];
            hope.Insert(0,dataH);

            Q.write(source, hope, false);
        }


        public static void write(string path, List<string> content, bool append = false)
        {
            using (TextWriter tw = new StreamWriter(File.Open(path, append ? FileMode.Append : FileMode.Create)))
            {
                foreach (var item in content)
                {
                    tw.WriteLine(item);
                }
            }
        }

        public static IDictionary<string,string> Parse(string XMLmsg)                 //Where the sausage gets made
        {
            string tagRex = "(<.*?>)|(.+?(?=</|$))";
            Regex findTag = new Regex(tagRex);
            string tabstrip = XMLmsg.Replace("\t", "");
            string carstrip = tabstrip.Replace("\r", "");
            string linstrip = carstrip.Replace("\n", "");
            XMLmsg = linstrip;                                                       //Strip the junk that breaks CSVs
            List<string> textList = findTag.Split(XMLmsg).ToList();                  //Split into an array(list) of taggish strings
            List<string> less = new List<string>();
            IDictionary<string, string> keyVP = new Dictionary<string, string>();
            for (int i = 0; i < textList.Count; i++)                                 //Remove blanks from the list of taggish items
            {
                if (textList[i] != "") { less.Add(textList[i]); }
            }
            for (int j = 0; j < less.Count; j++)                                     //j will be the index in the list
            {
                if (less[j].Length > 0)                                                      //not empty...
                {
                    if (less[j].Substring(0, 1) == "<" && less[j].Substring(0, 2) != "</")   //possible open tag
                    {
                        if (less[j].Substring(less[j].Length - 2) == "/>")           //isnt a close tag
                        {
                            int count = less[j].Count(x => x == '=');                //looking for mix of attribute values
                            switch (count)                                           // i.e. <Data Name='SubjectUserSid'>
                            {
                                case 0:                                              // empty value add KvP of Name and empty string
                                    //Console.WriteLine("Empty Tag: " + less[j]);
                                    keyVP.Add(less[j].Substring(1, (less[j].Length - 3)), "");
                                    break;
                                case 1:                                              // MS Timedate stamp, always UTC, epoch added for ELK/SPLUNK
                                    if (less[j].Substring(1, 11) == "TimeCreated")
                                    {
                                        //Console.WriteLine("Time Tag Attribute: " + less[j]);
                                        var ndx0 = less[j].IndexOf("=");
                                        var val0 = less[j].Substring((ndx0 + 2), 10);
                                        var val01 = less[j].Substring((ndx0 + 13), 13);
                                        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                                        var epoc = val0 + "T" + val01 + "Z";
                                        var dtob = DateTime.Parse(epoc);
                                        var epocMs = (dtob - epoch).TotalMilliseconds;
                                        keyVP.Add("Epoch",epocMs.ToString());
                                        keyVP.Add("DateCreated", val0);
                                        keyVP.Add("TimeCreated", val01);
                                        break;
                                    }
                                    else if (less[j].IndexOf("=") < less[j].Length && less[j].Substring(less[j].Length - 2) == "/>")
                                    {
                                        int split = less[j].IndexOf("=");
                                        int dataLen = less[j].Length - split - 5;
                                        string Head2 = less[j].Substring(1, split - 1);
                                        string Data2 = less[j].Substring((split + 2), dataLen);
                                        keyVP.Add(Head2, Data2);
                                    }
                                    goto default;
                                case 2:                                                              // i.e. <Execution ProcessID='4' ThreadID='96'/>
                                    //Console.WriteLine("Multi Attribute Value Set: " + less[j]);
                                    var ndx1 = less[j].IndexOf("=");
                                    var ndx2 = less[j].LastIndexOf("=");
                                    var pad = ndx2 - ndx1;
                                    var val1rg = (less[j].Substring((ndx1), pad));
                                    var ndx3 = val1rg.IndexOf(" ");
                                    var val1sz = ndx3 - 2;
                                    var val1 = less[j].Substring(1, (ndx1 - 1));
                                    var val1val = less[j].Substring((ndx1 + 2), (val1sz - 1));
                                    var val2 = less[j].Substring((ndx1 + ndx3 + 1), (pad - val1sz - 3));
                                    var val2val = less[j].Substring((ndx2 + 2), (less[j].Length - (ndx2 + 5)));
                                    keyVP.Add(val1, val1val);
                                    keyVP.Add(val2, val2val);
                                    break;

                                default:
                                    Console.WriteLine("Broken Logic on: " + less[j]);
                                    break;
                            }
                        }
                        else if (less[j].Length > 8 && less[j].Substring(0, 8) == "<EventID")
                        {
                            if (less[j + 2] == "</EventID>")
                            {
                                string data = less[j + 1];
                                keyVP.Add("EventID", data);
                            }
                        }
                        else if (less[j].Length > 14 && less[j].Substring(0, 10) == "<Data Name")
                        {
                            int split = less[j].Count(x => x == '=');
                            string Head = less[j].Substring(12, less[j].Length - 14);
                            string Data = less[j + 1];
                            if (less[j + 1] == "</Data>") { Data = ""; }
                            keyVP.Add(Head, Data);
                        }
                        else if (less[j].Length == (less[j + 2].Length - 1) && less[j].Substring(1) == less[j + 2].Substring(2))   //tags for an element with a value
                        {
                            var place = less[j].Substring(1, (less[j].Length - 2));
                            if (keyVP.ContainsKey(place)) { place = j + "_" + place; }
                            keyVP.Add(place, less[j + 1]);
                        }
                        else if (less[j].Length > 10)                                                                             //incase multiple data fields(this happens alot)
                        { if (less[j].Substring(0, 6) == "<Data>" && less[j].Substring(less[j].Length - 8) == "<Data/>")
                            {
                                keyVP.Add(j + "_Data", (less[j].Substring(7, (less[j].Length - 13))));
                            }
                        }
                        else if (less[j] == "<Data/>")
                        {
                            keyVP.Add(j + "_Data", "");
                        }
                    }
                }
            }
            return keyVP;
            
        }
    }

}


"@
 
Add-Type -TypeDefinition $Source -Language CSharp

################################################################################
####       Parameters
################################################################################

$PathLog = "C:\Users\Beastly\Desktop\Desk\misc\teamV 1\logs\"
[string]$Delimeter = "|"

################################################################################
####       Code
################################################################################
  
$TestPath = test-path $PathLog             ## Clean bad Characters from FileName
if($TestPath)  
{  
   Get-ChildItem -path $PathLog -Recurse |   
   Foreach-Object {   
      $newName = $_.name -replace '[~#%&*{}|:<>?/|"]', ''  
      $newName = $_.name -replace ' ', '_'
      if (-not ($_.name -eq $newname)){  
         Rename-Item -Path $_.fullname -newname ($newName)  
      }  
  }  
}  
else  
{
   write-host "Invalid path details.... Please run the script again and enter the valid path" -fore cyan  
}

$Collection = Get-ChildItem -path $PathLog -Recurse      ## Works on a single log or a directory
$fast = New-Object -TypeName faster.Q
[int]$total = 0;      

foreach($Log in $Collection)
{
    if($Log.Extension -like ".evtx"){                    ## Only logs
    $reader = $fast.Qlocal($Log.FullName,"*");
    [int[]]$codes = $fast.UID($reader);
    foreach($c in $codes)
    {
        $Xmls = $fast.PullX($Log.FullName,$c)
        $dict = $fast.proof($Log.FullName, $Xmls, $c.toString(), $Delimeter)
        $total += $Xmls.Count;
    }}
}

