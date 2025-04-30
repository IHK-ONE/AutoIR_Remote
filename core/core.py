from plugins.HijackAnalysis import *
from plugins.UserAnalysis import *
from plugins.ProcAnalysis import *
from plugins.FileAnalysis import *
from plugins.NetAnalysis import *
from plugins.BackdoorAnalysis import *
from plugins.LogAnalysis import *
from plugins.RookitUpload import *


def main(client):
    HijackAnalysis(client)
    UserAnalysis(client)
    ProcAnalysis(client)
    NetAnalysis(client)
    FileAnalysis(client)
    BackdoorAnalysis(client)
    LogAnalysis(client)
    RookitUpload(client)
