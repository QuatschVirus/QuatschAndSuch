using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

namespace Commons.Database
{
    public class Database
    {
        public const string EntryPath = "./Entries";
        public const string RecordPath = "./Records.xml";

        public readonly string basePath;

        public Record root;

        public Database()
        {
            root = new(this, null, "");
        }

        public Record GetRecord(string key) => root.Traverse(key);

        public void SaveRecord()
        {
            string path = Path.Combine(basePath, RecordPath);
            using var f = File.OpenWrite(path);
            DataContractSerializer dcs = new(typeof(Record));
            dcs.WriteObject(f, root.Partialize());
        }

        public void LoadRecord()
        {
            string path = Path.Combine(basePath, RecordPath);
            if (!File.Exists(path)) throw new FileNotFoundException("Could not find records file", path);
            using var f = File.OpenRead(path);
            DataContractSerializer dcs = new(typeof(Record));
            root = Record.FromPartial((PartialRecord) dcs.ReadObject(f), null, this);
        }
    }

    public class Record
    {
        readonly Database source;

        public readonly string Key;
        readonly Record parent;
        readonly Dictionary<string, Record> children = new();
        string entryfile;
        ulong entryOffset;

        public Record(Database source, Record parent, string key)
        {
            this.source = source;
            this.parent = parent;
            Key = key;
        }

        public Record Traverse(string key)
        {
            string primary = string.Concat(key.TakeWhile(c => c != '/'));
            string secondary = string.Concat(key.Skip(primary.Length + 1));
            return Child(primary).Traverse(secondary);
        }

        public Record Child(string key)
        {
            if (key == "..") return parent;
            if (key == ".") return this;
            Record c = new(source, this, key);
            if (children.TryAdd(key, c))
            {
                return c;
            } else
            {
                return children[key];
            }
        }

        public PartialRecord Partialize()
        {
            PartialRecord[] children = (from c in this.children select c.Value.Partialize()).ToArray();
            return new(Key, children, entryfile + ":" + entryOffset.ToString());
        }

        public static Record FromPartial(PartialRecord p, Record parent, Database db)
        {
            Record r = new(db, parent, p.key);
            foreach (var child in p.children)
            {
                r.children.Add(child.key, FromPartial(p, r, db));
            }
            if (p.entry != "")
            {
                int i = p.entry.LastIndexOf(':');
                r.entryfile = p.entry[..i];
                r.entryOffset = Convert.ToUInt64(p.entry[(i + 1)..]);
            }
            return r;
        }
    }

    [DataContract]
    public readonly struct PartialRecord
    {
        [DataMember]
        public readonly string key;

        [DataMember]
        public readonly PartialRecord[] children;

        [DataMember]
        public readonly string entry;

        public PartialRecord(string key, PartialRecord[] children, string entry)
        {
            this.key = key;
            this.children = children;
            this.entry = entry;
        }
    }
}
