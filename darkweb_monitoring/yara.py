from .models import YaraRule


def generate_webshell_yara(seed_text: str) -> list[YaraRule]:
    text = seed_text.lower()
    families = ["B374K", "WSO"]
    if "b374k" not in text and "wso" not in text:
        families.append("Generic_PHP_Webshell")

    rules: list[YaraRule] = []
    if "B374K" in families:
        rules.append(
            YaraRule(
                name="PHP_Webshell_B374K_Signatures",
                family="B374K",
                rationale="Targets B374K naming markers, PHP eval execution, and base64 decoding patterns.",
                rule="""rule PHP_Webshell_B374K_Signatures
{
  meta:
    description = "Detects B374K-style PHP web shell traits"
    author = "Darkweb Monitoring Agentic AI"
    severity = "high"
  strings:
    $family = "b374k" nocase
    $eval = "eval(" nocase
    $b64 = "base64_decode" nocase
    $cmd = "shell_exec" nocase
  condition:
    uint16(0) != 0x5a4d and $family and 2 of ($eval, $b64, $cmd)
}""",
            )
        )
    if "WSO" in families:
        rules.append(
            YaraRule(
                name="PHP_Webshell_WSO_Signatures",
                family="WSO",
                rationale="Targets WSO markers plus common PHP command execution helpers.",
                rule="""rule PHP_Webshell_WSO_Signatures
{
  meta:
    description = "Detects WSO-style PHP web shell traits"
    author = "Darkweb Monitoring Agentic AI"
    severity = "high"
  strings:
    $family = "WSO" nocase
    $cmd1 = "passthru(" nocase
    $cmd2 = "system(" nocase
    $cmd3 = "proc_open" nocase
    $b64 = "base64_decode" nocase
  condition:
    uint16(0) != 0x5a4d and $family and 2 of ($cmd1, $cmd2, $cmd3, $b64)
}""",
            )
        )
    if "Generic_PHP_Webshell" in families:
        rules.append(
            YaraRule(
                name="PHP_Webshell_Generic_Obfuscated_Execution",
                family="Generic PHP web shell",
                rationale="Catches obfuscated PHP execution and persistence phrases seen in shell-sale chatter.",
                rule="""rule PHP_Webshell_Generic_Obfuscated_Execution
{
  meta:
    description = "Detects generic obfuscated PHP web shell behavior"
    author = "Darkweb Monitoring Agentic AI"
    severity = "medium"
  strings:
    $php = "<?php"
    $eval = "eval(" nocase
    $b64 = "base64_decode" nocase
    $gzinflate = "gzinflate" nocase
    $htaccess = ".htaccess" nocase
    $cron = "cron" nocase
  condition:
    $php and 3 of ($eval, $b64, $gzinflate, $htaccess, $cron)
}""",
            )
        )
    return rules

