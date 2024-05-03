using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Commons.Database
{
    public abstract class DatabaseContext : DbContext
    {
        readonly string source;
        readonly string key;

        public DatabaseContext(string source, string key)
        {
            this.source = source;
            this.key = key;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            SqliteConnectionStringBuilder connectionStringBuilder = new()
            {
                DataSource = source,
                Password = key
            };
            optionsBuilder.UseSqlite(connectionStringBuilder.ConnectionString);
            base.OnConfiguring(optionsBuilder);
        }
    }
}
