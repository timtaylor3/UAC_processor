import errno
import os
import pandas as pd
import platform
import pyhashlookup as hl
import re 
import sqlite3
import sys
import tarfile
import time
import yara
from argparse import ArgumentParser

"""
Requirements:
pandas
pyhashlookup
yara
"""

"""
TODO:
- Add hashlookups to fs_timeline and filesystem
- Output that makes sense
- Replace prints with colored logs.
- ????
"""
__author__ = 'Tim Taylor'
__version__ = 'Very ALPHA'
__credit__ = ['Thiago Canozzo Lahr - https://github.com/tclahr/uac', 
              'MITRE Corp - https://github.com/mitre/yararules-python',
             'CIRCL - https://github.com/hashlookup/PyHashlookup']


class FileClass:
    def __init__(self):
        pass
                 
    def create_directory(self, path):
        """ Creates the directory and fails silently if it exists """
        if not os.path.exists(path):
            try:
                os.makedirs(path)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise

    def remove_file(self, filename):
        """ Removes the file and silently fails if not present """
        try:
            if os.path.isfile(filename):
                os.remove(filename)
                
        except OSError as error:
            if error.errno != EEXIST:
                raise
    
    def get_directory(self, root_path, find_dir):
        """ Returns all paths that end with the sub_dir """
        paths_found = list()
        for root, sub_dirs in os.walk(root_path, topdown=True):
            for path in sub_dirs:
                if find_dir == path:
                    full_path = os.path.join(root, path)
                    if os.path.isdir(full_path):
                        paths_found.append(full_path)
            return paths_found

    def get_directories(self, root_path, recurse=False):
        """ Returns all paths from root_path """
        paths_found = list()
        if recurse:
            for root, sub_dirs in os.walk(root_path, topdown=True):
                for path in sub_dirs:
                    full_path = os.path.join(root, path)
                    if os.path.isdir(full_path):
                        paths_found.append(full_path)
        else:
            dirs = os.listdir(root_path)
            for dir in dirs:
                full_path = os.path.join(root_path, dir)
                if os.path.isdir(full_path):
                    paths_found.append(full_path)
                    
        return paths_found
    
    def get_file(self, root_path, filename):
        """ Returns the first file matching """
        result = ''
        for root, sub_dirs, files in os.walk(root_path, topdown=True):
            for file in files:
                if file == filename:
                    result = os.path.join(root,file)
                    return result

    def get_files(self, root_path, filename):
        """ Returns all files matching """
        files_found = list()
        for root, sub_dirs, files in os.walk(root_path, topdown=True):
            for file in files:
                if file == filename:
                    files_found.append(os.path.join(root, file))
        return files_found
    
    def get_all_files(self, root_path):
        """ Returns all files """
        files_found = list()
        for root, sub_dirs, files in os.walk(root_path, topdown=True):
            for file in files:
                files_found.append(os.path.join(root, file))
        return files_found
    
    def get_files_by_ext(self, root_path, ext):
        """ Returns all files in the root_path matching ext) """
        files_found = list()
        
        for file in os.listdir(root_path):
            if file.endswith(ext):
                files_found.append(os.path.join(root_path, file))
                
class UACClass:
    def __init__(self, config_dict):
        self.config_dict = config_dict
        self.root_path = self.config_dict['root_path']
        self.current_outpath = self.config_dict['current_outpath']
        self.current_system = self.config_dict['current_system']
        self.current_host = self.config_dict['current_host']
        
        self.f = FileClass()
        self.system_db = self.config_dict['system_db']
        self.conn = sqlite3.connect(self.system_db)
        self.hash_df = pd.DataFrame()
        self.fs_df = pd.DataFrame()
        
    def decompress_collection_files(self):
        data_path = os.path.join(self.current_outpath, 'data')
        print('Un-TAR-ing {} to {}'.format(self.current_system, self.current_outpath))
        if tarfile.is_tarfile(self.current_system):
            with tarfile.open(self.current_system,'r') as tar:
                try:
                    tar.extractall(data_path)

                except tarfile.TarError:
                    print('Error Un-TAR-ing {}'.format(data_path))
                    
        self.root_path = data_path
        
                 
    def colon_to_dict(self, data):
        result_dict = dict()
        for line in data:
            line.strip()
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            result_dict[key] = [value]
        return result_dict
         
        
    def get_hostnamectl(self):
        """ 
        Gets system info
        """
        file = self.f.get_file(self.root_path, 'hostnamectl.txt')
        
        if not os.path.isfile(file):
            file = self.f.get_file(self.root_path, 'hostname.txt')   

        df = pd.DataFrame()
        if file:    
            with open(file) as fh:
                file_data = fh.readlines()  
                host_data = self.colon_to_dict(file_data) 
                host_data['uac_system'] = self.current_host 
                
                df = pd.DataFrame.from_dict(host_data)

        return df

  
    def get_ipconfig(self):
        """ 
        Parses ifconfi-a.txt 
        Fall back to 'ip-addr-show.txt'
        Need to modify to get inet6 line
        """
        df = pd.DataFrame()
        file = self.f.get_file(self.root_path, 'ip_addr_show.txt')
        if not os.path.isfile(file):
            file = self.f.get_file(self.root_path, 'ifconfig-a.txt')
            
        with open(file) as fh:
            file_data = fh.readlines() 

            pattern = re.compile(r"((([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])[ (\[]?(\.|dot)[ )\]]?){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))")    
            ip_dict = dict() 
            dev_list = list()
            ip_dict['uac_system'] = self.current_host 
            for line in file_data: 
                line = line.strip() 
                if pattern.search(line):  
                    d = line.split(' ')[-1].strip() 
                    ip = line.split(' ')[1].split('/')[0].strip()  
                    dev_list.append('{}: {}'.format(d, ip))
                ip_data= ', '.join(dev_list)
                ip_dict['IPAddress'] = [ip_data]   
                    
            df = pd.DataFrame.from_dict(ip_dict)
            return df

    def get_timezone(self):
        
        df = pd.DataFrame()
    
        tz_dict  = {'uac_system': self.current_host}
        
        file = self.f.get_file(self.root_path, 'timezone')
        if os.path.isfile(file):
            with open(file) as fh:
                file_data = fh.readlines() 
                file_data = file_data[0].strip()
                tz_dict = {'TimeZone': [file_data]}
                tz_dict['uac_system'] = [self.current_host]
        df = pd.DataFrame.from_dict(tz_dict)
        return df
    
    def get_passwd(self):
        passwd_df = pd.DataFrame()
        df = pd.DataFrame()
        passwd_list = list()
        file = self.f.get_file(self.root_path, 'passwd')
        if os.path.isfile(file):
            with open(file) as fh:
                file_data = fh.readlines() 
                for line in file_data:
                    line = line.strip()
                    entry = line.split(':')
                    entry_dict = dict()
                    entry_dict['uac_system'] = self.current_host
                    entry_dict['username'] = entry[0]
                    entry_dict['passwd'] = entry[1]
                    entry_dict['uid'] = entry[2]
                    entry_dict['gid'] = entry[3]
                    entry_dict['comment'] = entry[4]
                    entry_dict['home_dir'] = entry[5]
                    entry_dict['shell'] = entry[6].strip()
                    
                    passwd_df = passwd_df.append(entry_dict, ignore_index=True, sort=False)
                    
        passwd_df = passwd_df.applymap(str)
        passwd_df.to_sql('passwd', con=self.conn, if_exists='append', index=False, method=None)
                       
        
    def get_group(self):
        group_list = list()
        file = self.f.get_file(self.root_path, 'passwd')
        df = pd.DataFrame()
        group_df = pd.DataFrame()
        if os.path.isfile(file):
            with open(file) as fh:
                file_data = fh.readlines() 
                for line in file_data:
                    line = line.strip()
                    entry_dict = dict()
                    entry_dict['uac_system'] = self.current_host
                    entry = line.split(':')
                    entry_dict['group_name'] = entry[0]
                    entry_dict['passwd'] = entry[1]
                    entry_dict['gid'] = entry[2]
                    entry_dict['group_list'] = entry[3]
                    group_df = group_df.append(entry_dict, ignore_index=True, sort=False)
                         
            
        group_df = group_df.applymap(str)
        group_df.to_sql('group', con=self.conn, if_exists='append', index=False, method=None)
                          
                        
    def system_documentation(self):
        host_df = self.get_hostnamectl()
        ip_df = self.get_ipconfig()
        tz_df = self.get_timezone()
        system_details = pd.DataFrame()
        
        data_frames = [host_df, ip_df, tz_df]
        
        #sd_df = pd.join(data_frames, index=['uac-systems']).fillna('')
        sd_df = pd.merge(host_df, ip_df, left_on='uac_system', right_on='uac_system')
        sd_df = pd.merge(sd_df, tz_df, left_on='uac_system', right_on='uac_system')

        header = list()
        columns = sd_df.columns.values.tolist()
        values =['Static hostname','IPAddress','Operating System','Chassis', 'TimeZone','Architecture', 'uac_system']
        ip_address = list()
        for item in columns:
            if item in values:
                header.append(item)
            elif item.startswith('eth') or item.startswith('en') or item.startswith('vmnet'):
                header.append(item)
        
        system_details = sd_df[header].copy()
        system_details.rename(columns={'Static hostname':'Hostname',
                                    'Operating System':'OperatingSystem'}, inplace=True)

        system_details = system_details.applymap(str)
        system_details.to_sql('system_details', con=self.conn, if_exists='append', index=False, method=None)
        
    def ingest_hash_executables(self):
        file = self.f.get_file(self.root_path, 'hash_executables.sha1')
        header = ['SHA1', 'FullPath']
        if os.path.isfile(file):
            sha1_df = pd.read_csv(file, 
                                  delim_whitespace=True, 
                                  names=header, 
                                  index_col='FullPath')
        else:
            print('{} not found.'.format(file))
            
        file = self.f.get_file(self.root_path, 'hash_executables.md5')
        header = ['MD5', 'FullPath']
        if os.path.isfile(file):
            md5_df = pd.read_csv(file, 
                                 delim_whitespace=True, 
                                 names=header,
                                 index_col='FullPath')
        
        else:
            print('{} not found.'.format(file))    
        
        self.hash_df = pd.concat([sha1_df, md5_df], axis=1)
        self.hash_df['uac-system'] = self.current_host
        self.hash_df = self.hash_df.applymap(str)
        self.hash_df.to_sql('hash_executables', con=self.conn, if_exists='append', index=True, method=None)
            
       
    def ingest_bodyfile(self):
        
        file = self.f.get_file(self.root_path, 'bodyfile.txt')
        header = ['skip1','FullPath','inode','perm','UID','GID','size',
                  'atime','mtime','ctime','skip2']
        date_fields = ['atime','mtime','ctime']
        
        if os.path.isfile(file):
            df = pd.read_csv(file, delimiter='|', 
                             keep_default_na=False,
                             names=header,
                             usecols=header, 
                             parse_dates=date_fields, 
                             index_col=1)
            df = df.drop(['skip1', 'skip2'], axis=1)
            df['atime'] = pd.to_datetime(df['atime'], unit='s')
            df['mtime'] = pd.to_datetime(df['mtime'], unit='s')
            df['ctime'] = pd.to_datetime(df['ctime'], unit='s')
        
            self.fs_df = pd.merge(df, self.hash_df, how='left', left_on='FullPath', right_on='FullPath')                  
            self.fs_df.to_sql('filesystem', con=self.conn, if_exists='append', index=False, method=None)
            
            header = ['FullPath','inode','perm','UID','GID','size','atime','mtime','ctime', 'SHA1', 'MD5']
            self.fs_df = self.fs_df.reindex(columns=header)
            
            header = ['atime','FullPath','inode','perm','UID','GID','size','SHA1', 'MD5']
            atime_df = self.fs_df[header].copy()
            atime_df.rename(columns={'atime':'TimeStamp'}, inplace=True)
            atime_df['Type'] = 'atime'
            
            header = ['mtime','FullPath','inode','perm','UID','GID','size','SHA1', 'MD5']                     
            mtime_df = self.fs_df[header].copy()
            mtime_df.rename(columns={'mtime':'TimeStamp'}, inplace=True)
            mtime_df['Type'] = 'mtime'
            
            header = ['ctime','FullPath','inode','perm','UID','GID','size','SHA1', 'MD5']    
            ctime_df = self.fs_df[header].copy()
            ctime_df.rename(columns={'ctime':'TimeStamp'}, inplace=True)
            ctime_df['Type'] = 'ctime'
            
            df = pd.concat([atime_df, mtime_df, ctime_df]).sort_values(by=['TimeStamp','Type'])
            
            sql_stmt = 'CREATE TABLE IF NOT EXISTS "fs_timeline" ("TimeStamp" TEXT, "FullPath" TEXT,"Type" TEXT,"inode" TEXT,"perm" TEXT,"UID" TEXT,"GID" TEXT,"size" TEXT,"SHA1" TEXT,"MD5" TEXT)'
            c = self.conn.cursor()
            c.execute(sql_stmt)
            self.conn.commit()
            
            header = ['TimeStamp','Type','inode','perm','UID','GID','size','SHA1', 'MD5']  
            fs_timeline_df = df[header].copy().fillna('')
            fs_timeline_df= fs_timeline_df.astype(str)
            fs_timeline_df.to_sql('fs_timeline',con=self.conn,if_exists='append',index=True, index_label='FullPath')
            
            
        else:
            print('{} was not found'.format(file))
            
class FakeMatch(object):
    """A fake Match class that mimics the yara Match object.
    Used to indicate no match.
    """
    rule = None
    namespace = None
    
class YaraClass(UACClass):
    # https://yara.readthedocs.io/en/stable/yarapython.html
    # https://github.com/mitre/yararules-python
    def __init__(self, config_dict):
        super().__init__(config_dict)
        #self.conn = sqlite3.connect(self.system_db)

        #self.config_dict = config_dict
        #self.root_path = self.config_dict['root_path']
        #self.current_system = self.config_dict['current_system']
        #self.current_host = self.config_dict['current_host']
        #self.f = FileClass()
        #self.system_db = self.config_dict['system_db']
        #self.conn = sqlite3.connect(self.system_db)
        self.yara_df = pd.DataFrame()
        self.compiled_rules = self.compile_files(self.config_dict['yara_rules_path'])
        self.data_path= os.path.join(self.current_outpath, 'data')
        
        
    def yara_search_directory(self):
        files =  self.f.get_all_files(self.data_path)

        for match, filepath in self.match_files(files, rule_files=None, 
                                                compiled_rules=self.compiled_rules, 
                                                externals=None, raise_on_warn=False):
            
            column_names = ["Rule", "NameSpace", "FilePath"]
            
            if match.rule != None:
                s = pd.Series([match.rule, match.namespace, filepath])
                self.yara_df = self.yara_df.append(s,ignore_index=True).fillna('')
        
        mapping = {self.yara_df.columns[0]:'Rule', self.yara_df.columns[1]: 'NameSpace', self.yara_df.columns[2]: 'FilePath'}
        self.yara_df = self.yara_df.rename(columns=mapping)

        return self.yara_df
    
    def add_yara_results_to_db(self):
        self.yara_df.to_sql('yara_hits', self.conn, if_exists='append', index=False)
    
    def compile_files(self, rule_path, externals=None):
        rule_files = os.listdir(rule_path)
        
        if not rule_files:
            return (None, None)
        # compile rules
        rules = {}
        warnings = list()
        for filepath in rule_files:
            if filepath.endswith('.yar'):
                filepath = os.path.join(rule_path, filepath)
                rules[filepath] = filepath
        try:
    
            compiled_rules = yara.compile(
                filepaths=rules,
                externals=self.make_externals(base_externals=externals),
                error_on_warning=True
                )
        
        except yara.WarningError as e:
            compiled_rules = yara.compile(
                filepaths=rules,
                externals=self.make_externals(base_externals=externals)
                )
            warnings.append('{}'.format(e))
        except yara.Error as e:
            print('Error compiling {} rules: {}'.format(
                len(rules),
                ' '.join([rules[i] for i in rules])
                ), file=sys.stderr)
            raise
        return compiled_rules


    def yara_matches(self, compiled_sigs, filepath, externals=None):
        try:
            if externals:
                matches = compiled_sigs.match(filepath, externals=externals)
            else:
                matches = compiled_sigs.match(filepath)
        except yara.Error:
            print('Exception matching on file "{}"'.format(filepath), file=sys.stderr)
            raise
        if not matches:
            yield FakeMatch(), filepath
        for m in matches:
            yield m, filepath

            
    def make_externals(self, filepath='', filename='', fileext='', dirname='', base_externals=None):
        """Given a file name, extension, and dir OR a full file path string, return
        a dictionary suitable for the yara match() function externals argument.
        If base_externals dictionary provided, then initialize the externals with it.
        The externals created by this function are:
            filepath
            filename
            extension
        """
        # initialize return dict with optionally given values
        d = dict()
        if base_externals:
            d.update(base_externals)
        # if not filepath, but we do have filename and dirname
        if not filepath and filename and dirname:
            filepath = os.path.join(dirname, filename)
        # if no extension, but do have filename or filepath
        if not fileext:
            if filename:
                _, fileext = os.path.splitext(filename)
            elif filepath:
                _, fileext = os.path.splitext(filepath)
        # if no filename, but we have filepath
        if not filename and filepath:
            _, filename = os.path.split(filepath)
        # update return dict with common externals when processing a file
        d.update({'filepath': filepath, 'filename': filename, 'extension': fileext})
        # return the computed externals
        return d    
        
        
    def match_files(self, files, rule_files=None, compiled_rules=None, externals=None, raise_on_warn=False):
        """Given iterator of files to match against and either a list of files
        containing rules or a compiled rules object,
        YIELD a tuple of matches and filename.
        Optionally, if given an externals dict, use that as the initial
        externals values.  This function will add the following definitions:
            filename    :   name of file without directories
            filepath    :   full path including directories and filename
            extension   :   the filename's extension, if present
        """
        if not compiled_rules:
            # compile rules
            try:
                warnings, compiled_rules = self.compile_files(
                    rule_files,
                    self.make_externals(base_externals=externals)
                    )
            except yara.Error as e:
                print(
                    'Error compiling {} rule files: {}'.format(len(rule_files), e),
                    file=sys.stderr
                    )
                raise
            if warnings and raise_on_warn:
                raise Exception('\n'.join(warnings))
            if not compiled_rules:
                raise Exception('Rules not compiled')
        # iterate files to scan
        for fname in files:
            if os.path.isdir(fname):
                for root, _, walk_files in os.walk(fname):
                    for name in walk_files:
                        filepath = os.path.join(root, name)
                        extern_d = self.make_externals(
                            filename=name,
                            filepath=filepath,
                            base_externals=externals
                            )
                        for m, f in yara_matches(compiled_rules, filepath, extern_d):
                            yield m, f
            else:
                extern_d = self.make_externals(filepath=fname, base_externals=externals)
                for m, f in self.yara_matches(compiled_rules, fname, extern_d):
                    yield m, f

                    
class HashClass(UACClass):
    def __init__(self, config_dict):
        super().__init__(config_dict)
        self.conn = sqlite3.connect(self.system_db)
        self.df = pd.DataFrame()
        self.list_of_hashes = list()
        
        self.main()
        
    def main(self):
        self.get_hashes_to_lookup()
        self.misp_hashlookups()
        self.add_misp_hashes_to_db()
        
    def get_hashes_to_lookup(self):
        sql_stmt = 'SELECT DISTINCT SHA1 from fs_timeline where SHA1 != "";' 
        df = pd.read_sql_query(sql_stmt, self.conn)
        self.list_of_hashes = df['SHA1'].to_list() 
    
    def misp_hashlookups(self):
        lookups = hl.Hashlookup(r'https://hashlookup.circl.lu/') 
        results = lookups.sha1_bulk_lookup(self.list_of_hashes) 
        self.df= pd.json_normalize(results).fillna('') 

    def add_misp_hashes_to_db(self):
        self.df.to_sql('hashlookups', self.conn, if_exists='append', index=True, method=None)

    def get_misp_hash_from_db(self):
        sql_stmt = 'SELECT DISTINCT * from hashlookups;' 
        return pd.read_sql_query(sql_stmt, self.conn)
        
def main():
    parser = ArgumentParser(prog='UAC collection Processing', 
                            description='Parsing and Processing of a UAC collection.',
                            usage='%(prog)s [options]',
                            epilog='Version: {}'.format(__version__))
    parser.add_argument('-i', help='Specify a path to the top level collection (required)', action='store',dest='input_path')
    parser.add_argument('-o', help='Specify a path to the top level to write the output (required)', action='store',dest='output_path')
    parser.add_argument('-y', help='Specify a path to the yara rules (required)', action='store',dest='yara_rules_path')
    parser.add_argument('-v', help='Show version and exit.', action='store_true')
    args = parser.parse_args()
    
    if args.v:
        print('Version: {}'.format(__version__))
        print('Creator: {}\n'.format(__author__))
        #print('\n')
        print('This script made possible by:')
        for item in __credit__:
            print(item)
        sys.exit(0)
              
    script_start = time.time()
    
    if not args.input_path or not args.output_path:
        print('-i and -o are required')
        print('Version:{}'.format(__version__))
        sys.exit(1)
              
    if not os.path.isdir(args.input_path):
        print('-i was not a valid directory')
        print('Version:{}'.format(__version__))
        sys.exit(1)
              
    if not args.yara_rules_path:
        print('-y: Specify a path to the yara rules (required)')
        print('Version:{}'.format(__version__))
        sys.exit(1)     
        
    root_path = args.input_path
    output_path = args.output_path
    yara_rules_path = args.yara_rules_path
    
    f = FileClass()
    print('Creating {} if it does not exist'.format(output_path))
    f.create_directory(output_path)
    systems= f.get_all_files(root_path)
    
    for current_system in systems:
        current_host = os.path.split(current_system)[-1]
        current_host = current_host.split('.')[0]
        current_host = current_host.replace('uac-','')

        current_outpath = os.path.join(output_path, current_host)
        current_outpath = current_outpath.split('.')[0]
        
        print('Creating {}'.format(current_outpath))
        f.create_directory(current_outpath)
        
        current_db = '_'.join([current_host, 'events.db'])
        system_db = os.path.join(current_outpath, current_db)  
        
        config_dict = {'root_path': root_path,
                       'current_outpath': current_outpath,
                       'current_system': current_system,
                        'system_db': system_db,
                        'current_host': current_host,
                        'yara_rules_path': yara_rules_path}
              
        uac_parser = UACClass(config_dict)
        
        uac_parser.decompress_collection_files()
        uac_parser.system_documentation()
        uac_parser.get_passwd()
        uac_parser.get_group()
        uac_parser.ingest_hash_executables()
        uac_parser.ingest_bodyfile()
        y = YaraClass(config_dict)
        results = y.yara_search_directory()
        y.add_yara_results_to_db()
        hash_lookups = HashClass(config_dict)
        print('Data written to {}'.format(system_db))
        end_time = time.time()
        print('Start Time: {}'.format(script_start))
        print('End Time: {}'.format(end_time))
        elapse_time = (end_time - script_start)/60
        print('Elasped Time: {} minutes'.format('{0:,.2f}'.format(elapse_time)))
        print('Finished')
        
if __name__ == "__main__":
    
    os_type = platform.platform()
    
    if 'Windows' in os_type:
        print('This script will not function properly on a Windows OS.')
        print('OS Detected {}'.format(os_type))
    
    else:    
        if sys.version_info[0] == 3:
            main()
        
        else:
            print('Python 3 is required')
            print('Detected Python {}.{}.{}'.format(sys.version_info[0], sys.version_info[1], sys.version_info[2]))
                