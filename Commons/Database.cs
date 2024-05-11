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

namespace QuatschAndSuch.Database
{
    /// <summary>
    /// A construct for adding basic database functionality.
    /// Extend this class to create a Database model, and add a <see cref="DbSet{TEntity}">DbSet</see> for each table.
    /// Now just correctly define the type you want to make a table for using Attributes or the Fluent API
    /// </summary>
    public abstract class Database : DbContext
    {
        readonly string source;
        readonly string key;

        public Database(string source, string key)
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
