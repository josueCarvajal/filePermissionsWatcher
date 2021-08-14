#!/usr/bin/python
import stat,os,sys
from pwd import getpwnam,getpwuid
from grp import getgrgid


#Monitoring script to set up with cron when facing issues of wrong assigned privileges
#this script will change the ownership of the given file for the custom non root owner
#in this example we are using a log file as an example, change the path and the arrays to match the file names.
logs_dir="/opt/.../logs/"

#the uid of the <nonroot> group.
#change the <nonroot> for your non root user
nonroot_uid=getpwnam('<nonroot>').pw_uid

#requires chmod 600
audit_out = [
    "audit.out.log",
    "audit.out.log.1",
    "audit.out.log.2",
    "audit.out.log.3",
    "audit.out.log.4",
    "audit.out.log.5",
    "audit.out.log.6",
    "audit.out.log.7",
    "audit.out.log.8",
    "audit.out.log.9",
    "audit.out.log.10",
]
#requires chmod 644
audit_log = [
    "audit.log",
    "audit.log.1",
    "audit.log.2",
    "audit.log.3",
    "audit.log.4",
    "audit.log.5",
    "audit.log.6",
    "audit.log.7",
    "audit.log.8",
    "audit.log.9",
    "audit.log.10",
]

# Validate if the file is owned by root user
# @param String fullpath of the file
# @return boolean True if the file is owned by rood
def isRootOwner(file_path):
    #expected <nonroot> user
    fileOwner = str(getpwuid(os.stat(file_path).st_uid).pw_name)
    if fileOwner == "root":
        return True
    else:
        return False
     
# will delete all the permisions of the file for all
# user group and others
def resetPermissions(file_path):
    #read
    NO_USER_READ = ~stat.S_IREAD
    NO_GROUP_READ = ~stat.S_IRGRP
    NO_OTHER_READ = ~stat.S_IROTH
    #write
    NO_USER_WRITING = ~stat.S_IWUSR
    NO_GROUP_WRITING = ~stat.S_IWGRP
    NO_OTHER_WRITING = ~stat.S_IWOTH

    NO_READ = NO_USER_READ & NO_GROUP_READ & NO_OTHER_READ
    NO_WRITE = NO_USER_WRITING & NO_GROUP_WRITING & NO_OTHER_WRITING
    os.chmod(file_path, NO_READ & NO_WRITE)

# will fix the ownership to <nonroot>
def changeOwnership(file_path):
    print("Changing ownership from root to <nonroot> in: " + file_path)
    os.chown(file_path, nonroot_uid, -1)

# will launch the chmod 600 and 644 for the required files
def changePermissions(log_name,file_path):
    resetPermissions(file_path)
    if ".out" in log_name:
        #if out file chmod 600 required -rw-------
        os.chmod(file_path, 0o600)
    else:
        #if regular log file chmod 644 required -rw-rw-r--.
        os.chmod(file_path, 0o644)

# validate each audit.log file
def validateRegularLog(logList):
    for logFile in logList:
        currentPath = logs_dir+logFile
        if os.path.exists(currentPath):
            if isRootOwner(currentPath):
                changeOwnership(currentPath)
                changePermissions("audit.log", currentPath)

# validate each audit.log.out file
def validateOutLogFile(logList):
    for logFile in logList:
        currentPath =logs_dir+logFile
        if os.path.exists(currentPath):
            if isRootOwner(currentPath):
                changeOwnership(currentPath)
                changePermissions("audit.log.out", currentPath)

validateRegularLog(audit_log)
validateOutLogFile(audit_out)