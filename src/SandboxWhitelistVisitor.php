<?php
/** SandboxWhitelistVisitor class declaration
 * @package PHPSandbox
 */
namespace PHPSandbox;

use PHPParser\NodeVisitorAbstract,
    PHPParser\Node,
    PHPParser\Node\Name,
    PHPParser\Node\Arg,
    PHPParser\Node\Scalar\String,
    PHPParser\Node\Stmt\Class_,
    PHPParser\Node\Stmt\Interface_,
    PHPParser\Node\Stmt\Trait_,
    PHPParser\Node\Stmt\Global_,
    PHPParser\Node\Stmt\Function_,
    PHPParser\Node\Expr\FuncCall,
    PHPParser\Node\Expr\Variable;

/**
 * SandboxWhitelister class for PHP Sandboxes.
 *
 * This class takes parsed AST code and checks it against the passed PHPSandbox instance configuration to
 * autmatically whitelist sandboxed code functions, classes, etc. if the appropriate settings are configured.
 *
 * @namespace PHPSandbox
 *
 * @author  Elijah Horton <fieryprophet@yahoo.com>
 * @version 1.4
 */
class SandboxWhitelistVisitor extends NodeVisitorAbstract {
    /** The PHPSandbox instance to check against
     * @var PHPSandbox
     */
    protected $sandbox;
    /** SandboxWhitelistVisitor class constructor
     *
     * This constructor takes a passed PHPSandbox instance to check against for whitelisting sandboxed code.
     *
     * @param   PHPSandbox   $sandbox            The PHPSandbox instance to check against
     */
    public function __construct(PHPSandbox $sandbox){
        $this->sandbox = $sandbox;
    }
    /** Examine the current PHPParser_Node node against the PHPSandbox configuration for whitelisting sandboxed code
     *
     * @param   Node         $node               The sandboxed $node to examine
     */
    public function leaveNode(Node $node){
        if($node instanceof Class_ && is_string($node->name) && $this->sandbox->allow_classes && $this->sandbox->auto_whitelist_classes && !$this->sandbox->has_blacklist_classes()){
            $this->sandbox->whitelist_class($node->name);
            $this->sandbox->whitelist_type($node->name);
        } else if($node instanceof Interface_ && is_string($node->name) && $this->sandbox->allow_interfaces && $this->sandbox->auto_whitelist_interfaces && !$this->sandbox->has_blacklist_interfaces()){
            $this->sandbox->whitelist_interface($node->name);
        } else if($node instanceof Trait_ && is_string($node->name) && $this->sandbox->allow_traits && $this->sandbox->auto_whitelist_traits && !$this->sandbox->has_blacklist_traits()){
            $this->sandbox->whitelist_trait($node->name);
        } else if($node instanceof FuncCall && $node->name instanceof Name && $node->name->toString() == 'define' && $this->sandbox->allow_constants && $this->sandbox->auto_whitelist_constants && !$this->sandbox->is_defined_func('define') && !$this->sandbox->has_blacklist_consts()){
            $name = isset($node->args[0]) ? $node->args[0] : null;
            if($name && $name instanceof Arg && $name->value instanceof String && is_string($name->value->value) && $name->value->value){
                $this->sandbox->whitelist_const($name->value->value);
            }
        } else if($node instanceof Global_ && $this->sandbox->allow_globals && $this->sandbox->auto_whitelist_globals && $this->sandbox->has_whitelist_vars()){
            foreach($node->vars as $var){
                /**
                 * @var Variable    $var
                 */
                if($var instanceof Variable){
                    $this->sandbox->whitelist_var($var->name);
                }
            }
        } else if($node instanceof Function_ && is_string($node->name) && $node->name && $this->sandbox->allow_functions && $this->sandbox->auto_whitelist_functions && !$this->sandbox->has_blacklist_funcs()){
            $this->sandbox->whitelist_func($node->name);
        }
    }
}