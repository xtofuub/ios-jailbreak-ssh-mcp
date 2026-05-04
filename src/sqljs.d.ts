declare module "sql.js" {
  export type QueryExecResult = {
    columns: string[];
    values: unknown[][];
  };

  export type Database = {
    exec(sql: string): QueryExecResult[];
    close(): void;
  };

  export type SqlJsStatic = {
    Database: new (data?: Uint8Array) => Database;
  };

  export default function initSqlJs(config?: {
    locateFile?: (file: string) => string;
  }): Promise<SqlJsStatic>;
}
