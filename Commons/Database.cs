using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;

namespace Commons.Database
{
    //public class Database
    //{
    //    public const string EntryPath = "./Entries";
    //    public const string RecordPath = "./Records.xml";

    //    public readonly Dictionary<string, (ulong, uint)> lastFileIndex = new();

    //    public readonly string basePath;

    //    public Record root;

    //    public Database()
    //    {
    //        root = new(this, null, "");
    //    }

    //    public Record GetRecord(string key) => root.Traverse(key);

    //    public void SaveRecord()
    //    {
    //        string path = Path.Combine(basePath, RecordPath);
    //        using var f = File.OpenWrite(path);
    //        DataContractSerializer dcs = new(typeof(Record));
    //        dcs.WriteObject(f, root.Partialize());
    //    }

    //    public void LoadRecord()
    //    {
    //        string path = Path.Combine(basePath, RecordPath);
    //        if (!File.Exists(path)) throw new FileNotFoundException("Could not find records file", path);
    //        using var f = File.OpenRead(path);
    //        DataContractSerializer dcs = new(typeof(Record));
    //        root = Record.FromPartial((PartialRecord) dcs.ReadObject(f), null, this);
    //    }

    //    public Entry<T> CreatEntry<T>(Record at, T value)
    //    {

    //    }
    //}

    //public class Record
    //{
    //    readonly Database source;

    //    public readonly string Key;
    //    readonly Record parent;
    //    readonly Dictionary<string, Record> children = new();
    //    string entryfile;
    //    ulong entryOffset;
    //    uint indexInFile;

    //    public Record(Database source, Record parent, string key)
    //    {
    //        this.source = source;
    //        this.parent = parent;
    //        Key = key;
    //    }

    //    public Record Traverse(string key)
    //    {
    //        string primary = string.Concat(key.TakeWhile(c => c != '/'));
    //        string secondary = string.Concat(key.Skip(primary.Length + 1));
    //        return Child(primary).Traverse(secondary);
    //    }

    //    public Record Child(string key)
    //    {
    //        if (key == "..") return parent;
    //        if (key == ".") return this;
    //        Record c = new(source, this, key);
    //        if (children.TryAdd(key, c))
    //        {
    //            return c;
    //        } else
    //        {
    //            return children[key];
    //        }
    //    }

    //    public PartialRecord Partialize()
    //    {
    //        PartialRecord[] children = (from c in this.children select c.Value.Partialize()).ToArray();
    //        return new(Key, children, entryfile + ":" + entryOffset.ToString());
    //    }

    //    public static Record FromPartial(PartialRecord p, Record parent, Database db)
    //    {
    //        Record r = new(db, parent, p.key);
    //        foreach (var child in p.children)
    //        {
    //            r.children.Add(child.key, FromPartial(p, r, db));
    //        }
    //        if (p.entry != "")
    //        {
    //            int i = p.entry.LastIndexOf(':');
    //            r.entryfile = p.entry[..i];
    //            r.entryOffset = Convert.ToUInt64(p.entry[(i + 1)..]);
    //            if (!db.lastFileIndex.TryAdd(r.entryfile, (r.entryOffset, 0)))
    //            {
    //                var index = db.lastFileIndex[r.entryfile];
    //                if (index.Item1 < r.entryOffset)
    //                {
    //                    index.Item1 = r.entryOffset;
    //                    index.Item2++;
    //                }
    //            }
    //        }
    //        return r;
    //    }
    //}

    //public class Entry<T>
    //{
    //    Record key;
    //    T value;
    //}

    //public readonly struct PartialEntry<T>
    //{
    //    public readonly string key;
    //    public readonly T value;
    //}

    //[DataContract]
    //public readonly struct PartialRecord
    //{
    //    [DataMember]
    //    public readonly string key;

    //    [DataMember]
    //    public readonly PartialRecord[] children;

    //    [DataMember]
    //    public readonly string entry;

    //    public PartialRecord(string key, PartialRecord[] children, string entry)
    //    {
    //        this.key = key;
    //        this.children = children;
    //        this.entry = entry;
    //    }
    //}

    public class Database
    {
        readonly SqliteConnection dbConnection;

        public Database(string path, string key)
        {
            SqliteConnectionStringBuilder cSB = new()
            {
                DataSource = path,
                Password = key,
            };
            dbConnection = new SqliteConnection(cSB.ConnectionString);
            dbConnection.Open();
        }

        ~Database()
        {
            dbConnection.Close();
            dbConnection.Dispose();
        }

        public static string MapType(Type t)
        {

        }
    }

    /// <summary>
    /// Represents a collection stored on the database
    /// </summary>
    /// <typeparam name="T">The type of the stored objects</typeparam>
    public class DBCollection<T>
    {
        Database source;
        string tableName;

        /// <summary>
        /// Creates a new collection for the database. It maps the type in <c>T</c> to the columns
        /// </summary>
        /// <param name="source">The source database</param>
        /// <param name="tableName">The name of the table to save the collection to</param>
        /// <param name="mapDepth">The depth the mapping goes to. If this is greater than 0, it will also map the types of contained objects to this depth. Everyihing that is not mapped wil bes stored as a JSON string</param>
        public DBCollection(Database source, string tableName, int mapDepth = 0)
        {
            this.source = source;
            this.tableName = tableName;

        }
    }
}
