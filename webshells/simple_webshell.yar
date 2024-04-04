rule simple_webshell_php : webshell
{	
	meta:
		author = "devjanger"
		description = "Simple Webshell Detection rule"
	strings:
		$exec = /(exec|passthru|system|shell_exec|popen|proc_open|pcntl_exec)\(/i
		$eval = /(eval|assert)\(/i
		$info = /(phpinfo|posix_mkfifo|posix_getlogin|posix_ttyname|getenv|get_current_user|proc_get_status|get_cfg_var|disk_free_space|disk_total_space|diskfreespace|getcwd|getlastmo|getmygid|getmyinode|getmypid|getmyuid)\(/i
	condition:
		$exec or $eval or $info
}
