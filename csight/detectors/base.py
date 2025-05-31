from typing import Optional, Dict

def detect(packet_info: Dict) -> Optional[str]:
    # Each detector must override this function
    raise NotImplementedError("Each detector must override this function.")
