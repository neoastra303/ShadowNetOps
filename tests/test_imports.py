def test_redteam_import():
    from redteam import main
    assert callable(main)

def test_tools_import():
    from tools.network_recon import NetworkRecon
    from tools.vuln_scanner import VulnScanner
    from tools.osint_tools import OSINTTools
    from tools.dependency_manager import DependencyManager
    from tools.malware_analysis import MalwareAnalysisTools
    from tools.reverse_engineering import ReverseEngineeringTools
    from tools.cryptography_tools import CryptographyTools
    from tools.reporting import ReportingModule
    from tools.misc_utils import MiscUtilities

def test_config_manager_import():
    from config_manager import ConfigManager, get_config_manager