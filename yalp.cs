using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace faster
{
    static class GlobalOut {
        public static string OutDir = "";
    }
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

        public static string Hash(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        public string MID(EventLogReader log)                                               //Machine name
        {
            string machine = "";
            int i = 0;
            for (EventRecord eInst = log.ReadEvent(); i != 1; eInst = log.ReadEvent())
            { machine = eInst.MachineName; i++; }
            return machine;
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

        public void Proof(string path, ICollection<string> Xmls, string code, string d, string compu)     //Muti-Threaded High Level Parse
        {
            ConcurrentBag<string> Final = new ConcurrentBag<string>();
            var head = Xmls.ElementAt(0);
            string dataH = "\"";

            IDictionary<string, string> HEAD = Q.Parse(head, compu);
            foreach (string f in HEAD.Keys) { dataH += f + "\"" + d + "\""; }
            dataH = dataH.Substring(0, dataH.Length - 2);
            string pathdir = "";
            //string comput = compu.Replace(".","_");    //left over from parsing out machine name with MID now does hash instead
            if (!(GlobalOut.OutDir == "")) { pathdir = GlobalOut.OutDir; }
            else { pathdir = path.Substring(0, path.LastIndexOf("\\")); }
            string logfile = path.Split('\\').Last();
            logfile = logfile.Split('.').First();
            string source = pathdir + "\\" + compu + "_" + logfile + "_" + code + ".csv";

            int k = 0;
            var options = new ParallelOptions() { MaxDegreeOfParallelism = 400 };
            Parallel.ForEach(Xmls, options ,(currentfile) =>
            {
                IDictionary<string, string> FINALLY = Q.Parse(currentfile, compu);
                string data = "\"";
                foreach (string f in FINALLY.Values) { data += f + "\"" + d + "\""; }
                data = data.Replace("  ", " ");
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
            hope.Insert(0, dataH);

            Q.Write(source, hope, false);
        }


        public static void Write(string path, List<string> content, bool append = false)
        {
            using (TextWriter tw = new StreamWriter(File.Open(path, append ? FileMode.Append : FileMode.Create)))
            {
                foreach (var item in content)
                {
                    tw.WriteLine(item);
                }
            }
        }

        public static IDictionary<string, string> Parse(string XMLmsg, string sHash)       //Where the sausage gets made
        {
            string tagRex = "(<.*?>)|(.+?(?=</|$))";
            Regex findTag = new Regex(tagRex);
            string tabstrip = XMLmsg.Replace("\t", "");
            string carstrip = tabstrip.Replace("\r", "");
            string linstrip = carstrip.Replace("\n", "");
            XMLmsg = linstrip;                                                             //Strip the junk that breaks CSVs
            List<string> textList = findTag.Split(XMLmsg).ToList();                        //Split into an array(list) of taggish strings
            List<string> less = new List<string>();
            List<string> errors = new List<string>();
            IDictionary<string, string> keyVP = new Dictionary<string, string>();
            for (int i = 0; i < textList.Count; i++)                                       //Remove blanks from the list of taggish items
            {
                if (textList[i] != "") { less.Add(textList[i]); }
            }
            int Dindex = 1;
            for (int j = 0; j < less.Count; j++)                                           //j will be the index in the list
            {
                if (less[j].Length > 0)                                                      //not empty...
                {
                    if (less[j].Substring(0, 1) == "<" && less[j].Substring(0, 2) != "</")   //possible open tag
                    {
                        if (less[j].Substring(less[j].Length - 2) == "/>")                 //isnt a close tag
                        {
                            int count = less[j].Count(x => x == '=');                      //looking for mix of attribute values
                            switch (count)                                                 // i.e. <Data Name='SubjectUserSid'>
                            {
                                case 0:                                                    // empty value add KvP of Name and empty string
                                    keyVP.Add(less[j].Substring(1, (less[j].Length - 3)), "");
                                    break;
                                case 1:                                                    // MS Timedate stamp, always UTC, epoch added for ELK/SPLUNK
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
                                        keyVP.Add("Epoch", epocMs.ToString());
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
                                    break;
                                case 2:                                                    // i.e. <Execution ProcessID='4' ThreadID='96'/>
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
                                case 3:                                                     // i.e. <Provider EventSourceName="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" Name="Service Control Manager"/>
                                    var split1 = less[j].IndexOf("\' ", 0) + 2;
                                    var split2 = less[j].IndexOf("\' ", split1 + 1) + 2;
                                    var seg1 = less[j].Substring(1, split1 - 2);
                                    var seg2 = less[j].Substring(split1, split2 - 1 - split1);
                                    var seg3 = less[j].Substring(split2, less[j].Length - 2 - split2);
                                    var k1 = seg1.Substring(0, seg1.IndexOf("=", 0));
                                    var v1 = seg1.Substring(seg1.IndexOf("=", 0) + 1, seg1.Length - seg1.IndexOf("=", 0) - 1);
                                    var k2 = seg2.Substring(0, seg2.IndexOf("=", 0));
                                    var v2 = seg2.Substring(seg2.IndexOf("=", 0) + 1, seg2.Length - seg2.IndexOf("=", 0) - 1);
                                    var k3 = seg3.Substring(0, seg3.IndexOf("=", 0));
                                    var v3 = seg3.Substring(seg3.IndexOf("=", 0) + 1, seg3.Length - seg3.IndexOf("=", 0) - 1);
                                    keyVP.Add(k1, v1);
                                    keyVP.Add(k2, v2);
                                    keyVP.Add(k3, v3);
                                    //var check = 0;
                                    break;
                                default:
                                    //System.Console.WriteLine(less[j]);
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
                            keyVP.Add((Dindex + "_" + Head), Data);
                            Dindex++;
                        }
                        else if (less[j].Length == (less[j + 2].Length - 1) && less[j].Substring(1) == less[j + 2].Substring(2))   //tags for an element with a value
                        {
                            var place = less[j].Substring(1, (less[j].Length - 2));
                            if (keyVP.ContainsKey(place)) { place = Dindex + "_" + place; Dindex++; }
                            keyVP.Add(place, less[j + 1]);
                        }
                        else if (less[j].Length > 10)                                                                             //incase multiple data fields(this happens alot)
                        {
                            if (less[j].Substring(0, 6) == "<Data>" && less[j].Substring(less[j].Length - 8) == "<Data/>")
                            {
                                keyVP.Add(Dindex + "_Data", (less[j].Substring(7, (less[j].Length - 13))));
                                Dindex++;
                            }
                        }
                        else if (less[j] == "<Data/>")
                        {
                            keyVP.Add(Dindex + "_Data", "");
                            Dindex++;
                        }
                        else
                        {
                            //System.Console.WriteLine(less[j]);
                        }
                    }
                }
            }
            keyVP.Add("Source_Hash", sHash);
            return keyVP;

        }
    }



    public class Program
    {
        
        public static int Main(string[] args)
        {
            var watch = new System.Diagnostics.Stopwatch();
            watch.Start();
            if (args.Length == 0)
            {
                System.Console.WriteLine("");
                System.Console.WriteLine("Enter a path to an EVTX or a path to a directory of EVTX.");
                System.Console.WriteLine("");
                System.Console.WriteLine("I am tired of working on this so the CLI is NOT friendly");
                System.Console.WriteLine("");
                System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx");
                System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\Containing_EVTX\\");
                System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\ofDirectories\\Containing_EVTX\\");
                System.Console.WriteLine("");
                System.Console.WriteLine("     The only option is an output dir, no flag just an out Dir as the second arg... don't screw up ");
                System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx C:\\Path\\out\\");
                System.Console.WriteLine("");
                return 1;
            }

            string path = args[0].ToString();

            if (!(args[1] == "")) {
                GlobalOut.OutDir = args[1];
            }

            if (File.Exists(path))
            {
                System.Console.WriteLine(path);
                var Wlog = new Q();

                var reader = Wlog.Qlocal(path, "*");
                IEnumerable<int> codes = Wlog.UID(reader);
                reader.Dispose();
                string mach = Q.Hash(path);
                foreach (int c in codes)
                {
                    ICollection<string> Xmls = Wlog.PullX(path, c);
                    Wlog.Proof(path, Xmls, c.ToString(), "^", mach);
                }
                Console.WriteLine($"Execution Time: {watch.ElapsedMilliseconds} ms");
                return 1;
            }
            else if (Directory.Exists(path))
            {
                System.Console.WriteLine(path);
                string[] array = Directory.GetFiles(path, "*.evtx");
                if (array.Length > 0) {
                    Console.WriteLine("--- Files: ---");
                    Parallel.ForEach(array, (name) =>
                    {
                        Console.WriteLine(name + " Processing...");
                        var Wlog = new Q();

                        var reader = Wlog.Qlocal(name, "*");
                        IEnumerable<int> codes = Wlog.UID(reader);
                        reader.Dispose();
                        string mach = Q.Hash(name);
                        Parallel.ForEach(codes, (c) =>
                        {
                            ICollection<string> Xmls = Wlog.PullX(name, c);
                            Wlog.Proof(name, Xmls, c.ToString(), "^", mach);
                        });
                    });
                    watch.Stop();
                    Console.WriteLine($"Execution Time: {watch.ElapsedMilliseconds} ms");
                    return 1;
                }
                else if (Directory.GetDirectories(path).Length > 0) {
                    string[] recurse = Directory.GetDirectories(path);
                    foreach (string d in recurse) {
                        string[] sub = Directory.GetFiles(d, "*.evtx");
                        if (sub.Length > 0)
                        {
                            Console.WriteLine("--- Files: ---");
                            Parallel.ForEach(sub, (name) =>
                            {
                                Console.WriteLine(name + " Processing...");
                                var Wlog = new Q();

                                var reader = Wlog.Qlocal(name, "*");
                                IEnumerable<int> codes = Wlog.UID(reader);
                                reader.Dispose();
                                string mach = Q.Hash(name);
                                Parallel.ForEach(codes, (c) =>
                                {
                                    ICollection<string> Xmls = Wlog.PullX(name, c);
                                    Wlog.Proof(name, Xmls, c.ToString(), "^", mach);
                                });
                            });
                            watch.Stop();
                            Console.WriteLine($"Execution Time: {watch.ElapsedMilliseconds} ms");
                            return 1;
                        }
                        else
                        {
                            System.Console.WriteLine(path);
                            System.Console.WriteLine("Enter a path to an EVTX or a path to a directory of EVTX.");
                            System.Console.WriteLine("");
                            System.Console.WriteLine("I am tired of working on this so the CLI is NOT friendly");
                            System.Console.WriteLine("");
                            System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx");
                            System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\Containing_EVTX\\");
                            System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\ofDirectories\\Containing_EVTX\\");
                            System.Console.WriteLine("");
                            System.Console.WriteLine("     The only option is an output dir, no flag just an out Dir as the second arg... don't screw up ");
                            System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx C:\\Path\\out\\");
                            System.Console.WriteLine("Try harder...");
                        }
                    }

                }
            }
            else
            {
                // path doesn't exist.
                System.Console.WriteLine(path);
                System.Console.WriteLine("Enter a path to an EVTX or a path to a directory of EVTX.");
                System.Console.WriteLine("");
                System.Console.WriteLine("I am tired of working on this so the CLI is NOT friendly");
                System.Console.WriteLine("");
                System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx");
                System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\Containing_EVTX\\");
                System.Console.WriteLine("or   Yalp2.exe C:\\Path\\to\\Directory\\ofDirectories\\Containing_EVTX\\");
                System.Console.WriteLine("");
                System.Console.WriteLine("     The only option is an output dir, no flag just an out Dir as the second arg... don't screw up ");
                System.Console.WriteLine("i.e. Yalp2.exe C:\\Path\\to\\Security.evtx C:\\Path\\out\\");
                System.Console.WriteLine("Try harder...");
            }
            return 1;

        }



    }
}

