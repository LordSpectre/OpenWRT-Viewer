<?php

require __DIR__ . '/vendor/autoload.php';

use phpseclib3\Net\SSH2;
use phpseclib3\Exception\UnableToConnectException;
use phpseclib3\Exception\ConnectionClosedException;

// === GESTIONE RICHIESTE AJAX PER TOGGLE STATO REGOLE ===
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_rule_enabled') {
    header('Content-Type: application/json');
    $response = [];

    $ajax_router_ip = '192.168.10.1';
    $ajax_username = 'root';
    $ajax_password = 'Lcmanager';

    $rule_uci_name = $_POST['rule_uci_name'] ?? null;
    $is_enabled_str = $_POST['is_enabled'] ?? null;

    if (!$rule_uci_name || !preg_match('/^[a-zA-Z0-9_]+$/', $rule_uci_name) || strpos($rule_uci_name, 'anon_cfg_placeholder_') === 0) {
            if (strpos($rule_uci_name, 'anon_cfg_placeholder_') === 0) {
                $response['status'] = 'error';
                $response['message'] = "Cannot modify rules with placeholder ID ('" . htmlspecialchars($rule_uci_name) . "'). Assign an explicit name to the rule section in the OpenWrt configuration file (e.g., config rule 'MyRuleName').";
            } else {
                $response['status'] = 'error';
                $response['message'] = 'Invalid or missing rule ID for modification.';
            }
        echo json_encode($response);
        exit;
    }

    if ($is_enabled_str !== null) {
        $new_status_bool = filter_var($is_enabled_str, FILTER_VALIDATE_BOOLEAN);
        $new_uci_value = $new_status_bool ? '1' : '0';

        $ssh_mod = null;
        try {
            $ssh_mod = new SSH2($ajax_router_ip); 
            if (!$ssh_mod->login($ajax_username, $ajax_password)) {
                throw new Exception('Autenticazione SSH fallita per operazione di modifica.');
            }

            $commands = [
                "uci set firewall." . $rule_uci_name . ".enabled='" . $new_uci_value . "'",
                "uci commit firewall",
                "/etc/init.d/firewall reload"
            ];
            
            $all_commands_successful = true;
            $command_execution_errors = [];

            foreach ($commands as $cmd) {
                $ssh_mod->exec($cmd);
                if ($ssh_mod->getExitStatus() != 0) {
                    $all_commands_successful = false;
                    $command_execution_errors[] = "Command failed: " . htmlspecialchars($cmd) . " (Error: " . htmlspecialchars(trim($ssh_mod->getStdError())) . ")";
                    break; 
                }
            }

            if ($all_commands_successful) {
                $response['status'] = 'success';
                $response['message'] = "Rule '" . htmlspecialchars($rule_uci_name) . "' updated to: " . ($new_status_bool ? 'Enabled' : 'Disabled') . ". Firewall reloaded.";
            } else {
                $response['status'] = 'error';
                $response['message'] = "Error during UCI commands execution: " . implode(" | ", $command_execution_errors);
            }

        } catch (Exception $e) {
            $response['status'] = 'error';
            $response['message'] = "Exception during modify operation: " . htmlspecialchars($e->getMessage());
        } finally {
            if ($ssh_mod && $ssh_mod->isConnected()) {
                $ssh_mod->disconnect();
            }
        }
    } else {
        $response['status'] = 'error';
        $response['message'] = 'Enabling state missing during request';
    }
    echo json_encode($response);
    exit; 
}

// === INIZIO SEZIONE PHP PER RECUPERO E PARSING DATI (per caricamento pagina normale) ===
// Le variabili $router_ip, $username, $password per la visualizzazione principale della pagina
// sono definite qui sotto. Idealmente, dovrebbero provenire dalla stessa fonte di quelle AJAX.
$router_ip = '192.168.10.1';
$username = 'root';
$password = 'Lcmanager';

$firewall_config_path = '/etc/config/firewall';
$parsed_sections = [];
$rules_by_source_zone = [];
$defined_zone_names = [];
$error_message = null;

try {
    $ssh_display = new SSH2($router_ip); 
    if (!$ssh_display->login($username, $password)) {
        throw new Exception('SSH Auth failed. Cannot show data!');
    }

    $command = "cat " . escapeshellarg($firewall_config_path);
    $firewall_content = $ssh_display->exec($command);

    if ($firewall_content === false) {
        $error_detail = "Codice Uscita: " . $ssh_display->getExitStatus() . ", Errore STDERR: " . $ssh_display->getStdError();
        throw new Exception('Errore durante l\'esecuzione del comando cat per visualizzazione. ' . $error_detail);
    }
    if (empty(trim($firewall_content))) {
        throw new Exception('Il file /etc/config/firewall sembra essere vuoto durante la visualizzazione.');
    }

    $lines = explode("\n", $firewall_content);
    $current_section = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '#') === 0) {
            continue;
        }
        if (strpos($line, "config ") === 0) {
            if (!empty($current_section)) $parsed_sections[] = $current_section;
            $current_section = [];
            $parts = preg_split('/\s+/', $line, 3);
            $current_section['type'] = $parts[1];
            $current_section['uci_name'] = isset($parts[2]) ? trim($parts[2], "'\"") : null; 
        } elseif (strpos($line, "option ") === 0 || strpos($line, "list ") === 0) {
            $parts = preg_split('/\s+/', $line, 3);
            if (count($parts) < 2) continue; 
            $option_type = $parts[0];
            $option_name = $parts[1];
            $option_value = isset($parts[2]) ? trim($parts[2], "'\"") : '';

            if ($option_type === 'list') {
                if (!isset($current_section[$option_name]) || !is_array($current_section[$option_name])) {
                    $current_section[$option_name] = [];
                }
                $current_section[$option_name][] = $option_value;
            } else {
                $current_section[$option_name] = $option_value;
            }
        }
    }
    if (!empty($current_section)) $parsed_sections[] = $current_section;

    $temp_cfg_counter = 0;
    foreach($parsed_sections as $idx => &$section_ref) {
        if (empty($section_ref['uci_name']) && ($section_ref['type'] === 'rule' || $section_ref['type'] === 'redirect')) {
            $section_ref['uci_name'] = 'anon_cfg_placeholder_' . $temp_cfg_counter++;
        }
        if (!isset($section_ref['name']) && isset($section_ref['uci_name']) && strpos($section_ref['uci_name'], 'anon_cfg_placeholder_') !== 0) {
             $section_ref['name'] = $section_ref['uci_name'];
        }
    }
    unset($section_ref);

    $temp_zones_info = [];
    foreach ($parsed_sections as $section) {
        if ($section['type'] === 'zone' && isset($section['name'])) {
            if (!in_array($section['name'], $defined_zone_names)) $defined_zone_names[] = $section['name'];
            $temp_zones_info[$section['name']] = $section;
            if (!isset($rules_by_source_zone[$section['name']])) $rules_by_source_zone[$section['name']] = [];
        }
    }

    if (!in_array('wan', $defined_zone_names)) $defined_zone_names[] = 'wan';
    if (!isset($rules_by_source_zone['wan'])) $rules_by_source_zone['wan'] = [];
    if (!isset($rules_by_source_zone['unknown_source'])) $rules_by_source_zone['unknown_source'] = [];

    foreach ($parsed_sections as $section) {
        if ($section['type'] === 'rule' || $section['type'] === 'redirect') { 
            $source_zone = isset($section['src']) ? $section['src'] : 'wan'; 
            if ($section['type'] === 'rule' && !isset($section['src'])) $source_zone = 'unknown_source';
            if (!isset($rules_by_source_zone[$source_zone])) $rules_by_source_zone[$source_zone] = [];
            if ($section['type'] === 'redirect') $section['is_redirect'] = true;
            $rules_by_source_zone[$source_zone][] = $section;
            if ($source_zone === 'unknown_source' && !in_array('unknown_source', $defined_zone_names) && !empty($rules_by_source_zone['unknown_source'])) {
                 $defined_zone_names[] = 'unknown_source';
            } elseif ($source_zone !== 'unknown_source' && !in_array($source_zone, $defined_zone_names)){
                 $defined_zone_names[] = $source_zone;
            }
        }
    }
    
    $defined_zone_names = array_unique($defined_zone_names);
    if (isset($rules_by_source_zone['unknown_source']) && empty($rules_by_source_zone['unknown_source'])) {
        unset($rules_by_source_zone['unknown_source']);
        $defined_zone_names = array_filter($defined_zone_names, function($zn) { return $zn !== 'unknown_source'; });
    }
    
    usort($defined_zone_names, function ($a, $b) {
        $order = ['lan' => 0, 'wan' => 1]; $a_is_priority = isset($order[$a]); $b_is_priority = isset($order[$b]);
        if ($a_is_priority && $b_is_priority) return $order[$a] <=> $order[$b];
        elseif ($a_is_priority) return -1; elseif ($b_is_priority) return 1;
        return $a <=> $b;
    });

    if ($ssh_display && $ssh_display->isConnected()) {
        $ssh_display->disconnect();
    }

} catch (Exception $e) { 
    $error_message = "Errore critico durante caricamento dati: " . htmlspecialchars($e->getMessage());
}

?>
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenWrt Firewall Viewer</title>
    <style>
        body { font-family: sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
        .tabs-container { width: 100%; }
        .tab-buttons { list-style-type: none; padding: 0; margin: 0 0 20px 0; display: flex; border-bottom: 2px solid #ccc; }
        .tab-buttons li { padding: 10px 18px; cursor: pointer; background-color: #e0e0e0; margin-right: 5px; border-radius: 5px 5px 0 0; border: 1px solid #ccc; border-bottom: none;}
        .tab-buttons li.active { background-color: #fff; border: 2px solid #ccc; border-bottom: 2px solid #fff; position: relative; top: 2px; font-weight: bold; }
        .tab-content { display: none; padding: 20px; background-color: #fff; border: 1px solid #ddd; border-top: none; }
        .tab-content.active { display: block; }
        h1 { text-align: center; color: #555; }
        h2 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; }
        th { background-color: #f0f0f0; }
        .error-message { color: #721c24; background-color: #f8d7da; border: 1px solid #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border-radius: .25rem; }
        
        .col-enabled { width: 8%; text-align: center; }
        .col-name { width: 20%; }
        .col-match { width: 52%; }
        .col-action { width: 20%; }

        .protocol { text-transform: uppercase; }
        .action-accept { color: green; font-weight: bold; }
        .action-drop { color: red; font-weight: bold; }
        .action-reject { color: orange; font-weight: bold; }
        .match-detail { display: block; margin-bottom: 3px; }
        code { background-color: #f0f0f0; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
        input[type="checkbox"] { transform: scale(1.2); cursor: pointer; }
        .status-message { padding: 10px; margin-top: 15px; border-radius: 4px; display: none; position: fixed; top: 10px; left: 50%; transform: translateX(-50%); z-index: 1000; min-width: 300px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
        .status-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>

    <h1>OpenWRT Firewall rules viewer</h1>
    <div id="ajax-status-message" class="status-message"></div>

    <?php if ($error_message && empty($parsed_sections)): ?>
        <div class="error-message"><?php echo $error_message; ?></div>
    <?php else: ?>
        <div class="tabs-container">
            <ul class="tab-buttons">
                <?php foreach ($defined_zone_names as $index => $zone_name): ?>
                    <li class="<?php echo $index === 0 ? 'active' : ''; ?>" onclick="openTab(event, '<?php echo htmlspecialchars($zone_name); ?>')">
                        <?php 
                        $display_name = htmlspecialchars(ucfirst($zone_name));
                        if (strtolower($zone_name) === 'wan') $display_name .= " (Port Forwarding)";
                        echo $display_name;
                        ?>
                    </li>
                <?php endforeach; ?>
            </ul>

            <?php foreach ($defined_zone_names as $index => $zone_name): ?>
                <div id="<?php echo htmlspecialchars($zone_name); ?>" class="tab-content <?php echo $index === 0 ? 'active' : ''; ?>">
                    <h2>Rules for Zone: <?php echo htmlspecialchars(ucfirst($zone_name)); ?></h2>
                    <?php if (isset($rules_by_source_zone[$zone_name]) && !empty($rules_by_source_zone[$zone_name])): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th class="col-enabled">Enabled</th>
                                    <th class="col-name">Name</th>
                                    <th class="col-match">Match</th>
                                    <th class="col-action">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($rules_by_source_zone[$zone_name] as $rule): ?>
                                    <tr>
                                        <td class="col-enabled">
                                            <?php
                                            $is_enabled = (!isset($rule['enabled']) || $rule['enabled'] == '1');
                                            $uci_name_attr = isset($rule['uci_name']) ? htmlspecialchars($rule['uci_name']) : '';
                                            ?>
                                            <input type="checkbox" class="enable-rule-checkbox" 
                                                   data-uci-name="<?php echo $uci_name_attr; ?>"
                                                   <?php echo $is_enabled ? 'checked' : ''; ?>
                                                   <?php echo empty($uci_name_attr) || strpos($uci_name_attr, 'anon_cfg_placeholder_') === 0 ? 'disabled title="Questa regola anonima (o senza nome UCI valido nel file) non può essere modificata direttamente con questo tool. Assegna un nome alla sezione nel file di config per abilitare la modifica."' : ''; ?> > 
                                        </td>
                                        <td><?php echo isset($rule['name']) ? htmlspecialchars($rule['name']) : 'N/A'; ?></td>
                                        <td>
                                            <?php
                                            if (isset($rule['is_redirect']) && $rule['is_redirect']) echo "<div class='match-detail'><strong>Type: Redirect</strong></div>";
                                            else echo "<div class='match-detail'><strong>Type: Firewall Rule</strong></div>";
                                            if (isset($rule['family']) && !empty($rule['family'])) echo "<div class='match-detail'>IP Family: " . htmlspecialchars(strtoupper($rule['family'])) . "</div>";
                                            if (isset($rule['proto'])) {
                                                $protocols = is_array($rule['proto']) ? $rule['proto'] : [$rule['proto']];
                                                if (!empty(array_filter($protocols))) echo "<div class='match-detail'>Protocol: <span class='protocol'>" . htmlspecialchars(implode(' / ', $protocols)) . "</span></div>";
                                            }
                                            $from_details = [];
                                            if (isset($rule['src']) && $rule['src'] !== '*' && $rule['src'] !== $zone_name) $from_details[] = "Source Zone: " . htmlspecialchars($rule['src']);
                                            if (isset($rule['src_ip'])) { $val = is_array($rule['src_ip']) ? implode(', ', $rule['src_ip']) : $rule['src_ip']; if(!empty(trim($val))) $from_details[] = "Source IP: " . htmlspecialchars($val); }
                                            if (isset($rule['src_mac'])) { $val = is_array($rule['src_mac']) ? implode(', ', $rule['src_mac']) : $rule['src_mac']; if(!empty(trim($val))) $from_details[] = "Source MAC: " . htmlspecialchars($val); }
                                            if (isset($rule['src_port'])) { $val = is_array($rule['src_port']) ? implode(', ', $rule['src_port']) : $rule['src_port']; if(!empty(trim($val))) $from_details[] = "Source Port: " . htmlspecialchars($val); }
                                            if (!empty($from_details)) echo "<div class='match-detail'><strong>From:</strong> " . implode('; ', $from_details) . "</div>";

                                            if ($rule['type'] === 'rule') {
                                                $to_details = [];
                                                if (isset($rule['dest']) && $rule['dest'] !== '*') $to_details[] = "Destination Zone: " . htmlspecialchars($rule['dest']);
                                                if (isset($rule['dest_ip'])) { $val = is_array($rule['dest_ip']) ? implode(', ', $rule['dest_ip']) : $rule['dest_ip']; if(!empty(trim($val))) $to_details[] = "Destination IP: " . htmlspecialchars($val); }
                                                if (isset($rule['dest_port'])) { $val = is_array($rule['dest_port']) ? implode(', ', $rule['dest_port']) : $rule['dest_port']; if(!empty(trim($val))) $to_details[] = "Destination Port: " . htmlspecialchars($val); }
                                                if (!empty($to_details)) echo "<div class='match-detail'><strong>TO:</strong> " . implode('; ', $to_details) . "</div>";
                                            }
                                            if (isset($rule['is_redirect']) && $rule['is_redirect']) {
                                                if (isset($rule['src_dip'])) { $val = is_array($rule['src_dip']) ? implode(', ', $rule['src_dip']) : $rule['src_dip']; if(!empty(trim($val))) echo "<div class='match-detail'>Su IP Esterno (WAN): " . htmlspecialchars($val) . "</div>"; }
                                                if (isset($rule['src_dport'])) { $val = is_array($rule['src_dport']) ? implode(', ', $rule['src_dport']) : $rule['src_dport']; if(!empty(trim($val))) echo "<div class='match-detail'>Porta Esterna: " . htmlspecialchars($val) . "</div>"; }
                                                $forward_to_details = [];
                                                if (isset($rule['dest_ip'])) { $val = is_array($rule['dest_ip']) ? implode(', ', $rule['dest_ip']) : $rule['dest_ip']; if(!empty(trim($val))) $forward_to_details[] = "Internal IP: " . htmlspecialchars($val); }
                                                if (isset($rule['dest_port'])) { $val = is_array($rule['dest_port']) ? implode(', ', $rule['dest_port']) : $rule['dest_port']; if(!empty(trim($val))) $forward_to_details[] = "Internal Port: " . htmlspecialchars($val); }
                                                if (!empty($forward_to_details)) echo "<div class='match-detail'><strong>Forward to:</strong> " . implode('; ', $forward_to_details) . "</div>";
                                            }
                                            if (isset($rule['limit'])) { $limit_str = "Limite: " . htmlspecialchars($rule['limit']); if (isset($rule['limit_burst'])) $limit_str .= ", Burst: " . htmlspecialchars($rule['limit_burst']); echo "<div class='match-detail'>" . $limit_str . "</div>"; }
                                            if (isset($rule['extra']) && !empty(trim($rule['extra']))) echo "<div class='match-detail'>Extra Arguments: <code>" . htmlspecialchars($rule['extra']) . "</code></div>";
                                            ?>
                                        </td>
                                        <td>
                                            <?php
                                            $action_target = isset($rule['target']) ? strtoupper($rule['target']) : 'N/A'; $action_display_text = $action_target; $action_context = ''; $action_class_name = '';
                                            if (isset($rule['is_redirect']) && $rule['is_redirect']) { $action_display_text = "REDIRECT (DNAT)"; } 
                                            else if ($rule['type'] === 'rule') {
                                                $has_src = isset($rule['src']) && $rule['src'] !== '*'; $has_dest = isset($rule['dest']) && $rule['dest'] !== '*';
                                                if ($has_src && $has_dest) $action_context = ' forward';
                                                elseif ($has_src && !$has_dest) $action_context = ' input';
                                                elseif (!$has_src && $has_dest) $action_context = ' output';
                                                $action_display_text .= $action_context;
                                                if ($action_target === 'ACCEPT') $action_class_name = 'action-accept';
                                                elseif ($action_target === 'DROP') $action_class_name = 'action-drop';
                                                elseif ($action_target === 'REJECT') $action_class_name = 'action-reject';
                                            }
                                            if (!empty($action_class_name)) echo "<span class='" . $action_class_name . "'>" . htmlspecialchars($action_display_text) . "</span>";
                                            else echo htmlspecialchars($action_display_text);
                                            ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php else: ?>
                        <p>No rules or redirect for this zone '<?php echo htmlspecialchars($zone_name); ?>'.</p>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>

        <script>
            function openTab(evt, zoneName) {
                var i, tabcontent, tablinks;
                tabcontent = document.getElementsByClassName("tab-content");
                for (i = 0; i < tabcontent.length; i++) tabcontent[i].classList.remove("active");
                tablinks = document.getElementsByClassName("tab-buttons")[0].getElementsByTagName("li");
                for (i = 0; i < tablinks.length; i++) tablinks[i].classList.remove("active");
                document.getElementById(zoneName).classList.add("active");
                evt.currentTarget.classList.add("active");
            }

            document.addEventListener('DOMContentLoaded', function () {
                const checkboxes = document.querySelectorAll('.enable-rule-checkbox');
                const statusMessageDiv = document.getElementById('ajax-status-message');
                var statusMessageTimeout;

                checkboxes.forEach(function (checkbox) {
                    if (checkbox.disabled) return; 

                    checkbox.addEventListener('change', function () {
                        const ruleUciName = this.dataset.uciName;
                        const isEnabled = this.checked;
                        
                        this.disabled = true; 
                        clearTimeout(statusMessageTimeout); 
                        statusMessageDiv.style.display = 'none'; 

                        const formData = new FormData();
                        formData.append('action', 'toggle_rule_enabled');
                        formData.append('rule_uci_name', ruleUciName);
                        formData.append('is_enabled', isEnabled);

                        fetch('index.php', { method: 'POST', body: formData })
                        .then(response => {
                            if (!response.ok) { throw new Error('Network response NOT OK: ' + response.status + " " + response.statusText); }
                            return response.json();
                        })
                        .then(data => {
                            statusMessageDiv.textContent = data.message;
                            statusMessageDiv.className = 'status-message'; 
                            if (data.status === 'success') {
                                statusMessageDiv.classList.add('status-success');
                            } else {
                                statusMessageDiv.classList.add('status-error');
                                this.checked = !isEnabled; 
                            }
                            statusMessageDiv.style.display = 'block';
                            statusMessageTimeout = setTimeout(() => { statusMessageDiv.style.display = 'none'; }, 5000); 
                        })
                        .catch(error => {
                            console.error('Errore Fetch:', error);
                            statusMessageDiv.textContent = 'Comunication error: ' + error.message;
                            statusMessageDiv.className = 'status-message status-error';
                            statusMessageDiv.style.display = 'block';
                            this.checked = !isEnabled; 
                            statusMessageTimeout = setTimeout(() => { statusMessageDiv.style.display = 'none'; }, 5000);
                        })
                        .finally(() => {
                            this.disabled = false; 
                        });
                    });
                });
            });
        </script>
    <?php endif; ?>

</body>
</html>
