<?php
// RoCATPCHA plugin
// By Vojtěch Oram http://vojtechoram.cz/
// Version 1.0
// For myBB 1.6.x

// Tell MyBB when to run the hooks
// $plugins->add_hook("hook name", "function name");
$plugins->add_hook("member_register_start", "rocaptcha_display");
$plugins->add_hook('datahandler_user_validate', 'rocaptcha_verify');

// The information that shows up on the plugin manager
// Note that the name of the function before _info, _activate, _deactivate must be the same as the filename before the extension.
function rocaptcha_info()
{
	return array(
		"name"			=> "RoCAPTCHA Plugin",
		"description"	=> "Allows image verification provided by RoCATPCHA",
		"website"		=> "http://rocaptcha.com",
		"author"		=> "Vojtěch Oram",
		"authorsite"	=> "http://vojtechoram.cz",
		"version"		=> "1.0",
		"guid"			=> "54c4ca86c201523a393dd9c3a7854742"
	);
}

// This function runs when the plugin is activated.
function rocaptcha_activate()
{
	
	global $db, $mybb, $lang;

	$lang->load("rocaptcha");
	
	$new_template = array(
		"tid"		=> NULL,
		"title"		=> 'register_captcha',
		"template"	=> $db->escape_string('<br /> 
		<fieldset class="trow2">
		<legend><strong>{$lang->rocaptcha_verification}<strong></legend>
		<table cellspacing="0" cellpadding="{$theme[\'tablespace\']}"><tr>
		<td><span class="smalltext">{$lang->rocaptcha_note}</span><br/><br/>{$captcha_image}</td>
		</tr>
		</table></fieldset>'),
		"sid"		=> "-1",
		"version"	=> "1.0",	
		"dateline"	=> "1368946969",
	);

	$db->insert_query("templates", $new_template);
	
	
	require MYBB_ROOT.'/inc/adminfunctions_templates.php';
	// MEMBERPROFILE
	find_replace_templatesets("member_register", '#{\$regimage}#', "{\$captcha}{\$regimage}");
	
	
		$captcha_group = array(
		"name"			=> "captcha_group",
		"title"			=> "RoCAPTCHA Settings.",
		"description"	=> "New users need to verify a RoCAPTCHA image before completing the registration.",
		"disporder"		=> "25",
		"isdefault"		=> "no",
	);

	$db->insert_query("settinggroups", $captcha_group);
	$gid = $db->insert_id();

		$new_setting = array(
		'name'			=> 'captcha_status',
		'title'			=> 'RoCATPCHA status',
		'description'	=> 'Show RoCAPTCHA While New User Tries To Register?',
		'optionscode'	=> 'yesno',
		'value'			=> 'no',
		'disporder'		=> '1',
		'gid'			=> intval($gid)
	);

	$db->insert_query('settings', $new_setting);
		
	$new_setting2 = array(
		'name'			=> 'captcha_public',
		'title'			=> 'RoCATPCHA public key',
		'description'	=> 'Enter your RoCAPTCHA public key here, you can obtain this here: http://rocaptcha.com/register',
		'optionscode'	=> 'text',
		'value'			=> '',
		'disporder'		=> '2',
		'gid'			=> intval($gid)
	);

	$db->insert_query('settings', $new_setting2);

		$new_setting3 = array(
		'name'			=> 'captcha_private',
		'title'			=> 'RoCATPCHA private key',
		'description'	=> 'Enter your RoCAPTCHA private key here, you can obtain it here: http://rocaptcha.com/register',
		'optionscode'	=> 'text',
		'value'			=> '',
		'disporder'		=> '3',
		'gid'			=> intval($gid)
	);

	$db->insert_query('settings', $new_setting3);

		$new_setting5 = array(
		'name'			=> 'captcha_language',
		'title'			=> 'RoCATPCHA Language',
		'description'	=> 'Which language is used in the interface.',
        "optionscode" => "select
en= English
cs= Czech",
		'value'			=> 'en',
		'disporder'		=> '5',
		'gid'			=> intval($gid),
	);

	$db->insert_query('settings', $new_setting5);
	
	rebuildsettings();
}

// This function runs when the plugin is deactivated.
function rocaptcha_deactivate()
{
	global $mybb, $db;
	$db->query("DELETE FROM ".TABLE_PREFIX."templates WHERE title = 'register_captcha'");

	$db->query("DELETE FROM ".TABLE_PREFIX."settings WHERE name='captcha_status'");
	$db->query("DELETE FROM ".TABLE_PREFIX."settings WHERE name='captcha_public'");
	$db->query("DELETE FROM ".TABLE_PREFIX."settings WHERE name='captcha_private'");
	$db->delete_query("settinggroups","name='captcha_group'");

	require MYBB_ROOT.'/inc/adminfunctions_templates.php';
	//REMOVING tags
	find_replace_templatesets("member_register", '#'.preg_quote('{$captcha}').'#', '',0);

	rebuildsettings();

	
}

// This is the function that is run when the hook is called.
// It must match the function name you placed when you called add_hook.
// You are not just limited to 1 hook per page.  You can add as many as you want.
function rocaptcha_display()
{
	global $db, $mybb, $templates, $captcha, $theme, $lang;
	
	$lang->load("rocaptcha");
	
	require_once('rocaptchalib.php');
	if($mybb->settings['captcha_status'] != "no" && $mybb->settings['captcha_public']!= "" && $mybb->settings['captcha_private'] != ""){
		$publickey = $mybb->settings['captcha_public'];
		$captcha_image = RoCaptcha::getHtml($publickey, null, $mybb->settings['captcha_language']);
		eval("\$captcha = \"".$templates->get("register_captcha")."\";");
	}
}

function rocaptcha_verify($reg){

	global $db, $mybb, $templates, $captcha, $lang;
	
	$lang->load("rocaptcha");
	
	
	if($mybb->settings['captcha_status'] != "no" && $mybb->settings['captcha_public']!= "" && $mybb->settings['captcha_private'] != ""){
		if(strpos($_SERVER['REQUEST_URI'], 'member.php')){
			
			require_once('rocaptchalib.php');
			$privatekey = $mybb->settings['captcha_private'];
			$resp = RoCaptcha::checkAnswer ($privatekey,
			                                $_POST["rocaptcha_challenge_field"],
			                                $_POST["rocaptcha_response_field"],
											$_POST["rocaptcha_session_id"]);
			
			if (!$resp->is_valid) {
				$reg->set_error($db->escape_string($lang->rocaptcha_failed . ($resp->error ? "({$resp->error})" : "")));
				return $reg;
			}
		}
	}
}


// End of plugin.
?>