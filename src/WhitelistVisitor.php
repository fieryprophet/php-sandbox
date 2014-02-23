<?php
    /** WhitelistVisitor class declaration
     * @package PHPSandbox
     */
    namespace PHPSandbox;

    use PhpParser\NodeVisitorAbstract,
        PhpParser\Node,
        PhpParser\Node\Name,
        PhpParser\Node\Arg,
        PhpParser\Node\Scalar\String,
        PhpParser\Node\Stmt\Namespace_,
        PhpParser\Node\Stmt\Class_,
        PhpParser\Node\Stmt\Interface_,
        PhpParser\Node\Stmt\Trait_,
        PhpParser\Node\Stmt\Use_,
        PhpParser\Node\Stmt\UseUse,
        PhpParser\Node\Stmt\Global_,
        PhpParser\Node\Stmt\Function_,
        PhpParser\Node\Stmt\StaticVar,
        PhpParser\Node\Expr\ConstFetch,
        PhpParser\Node\Expr\FuncCall,
        PhpParser\Node\Expr\Variable,
        PhpParser\Node\Expr\New_;
    
    /**
     * Whitelister class for PHP Sandboxes.
     *
     * This class takes parsed AST code and checks it against the passed PHPSandbox instance configuration to
     * autmatically whitelist trusted code functions, classes, etc. if the appropriate settings are configured.
     *
     * @namespace PHPSandbox
     *
     * @author  Elijah Horton <fieryprophet@yahoo.com>
     * @version 1.4
     */
    class WhitelistVisitor extends NodeVisitorAbstract {
        /** The PHPSandbox instance to check against
         * @var PHPSandbox
         */
        protected $sandbox;
        /** WhitelistVisitor class constructor
         *
         * This constructor takes a passed PHPSandbox instance to check against for whitelisting trusted code.
         *
         * @param   PHPSandbox   $sandbox            The PHPSandbox instance to check against
         */
        public function __construct(PHPSandbox $sandbox){
            $this->sandbox = $sandbox;
        }
        /** Examine the current PhpParser_Node node against the PHPSandbox configuration for whitelisting trusted code
         *
         * @param   Node   $node          The trusted $node to examine
         *
         * @return  null|bool         Return false if node must be removed, or null if no changes to the node are made
         */
        public function leaveNode(Node $node){
            if($node instanceof FuncCall && $node->name instanceof Name && !$this->sandbox->has_blacklist_funcs()){
                $this->sandbox->whitelist_func($node->name->toString());
            } else if($node instanceof Function_ && is_string($node->name) && $node->name && !$this->sandbox->has_blacklist_funcs()){
                $this->sandbox->whitelist_func($node->name);
            } else if(($node instanceof Variable || $node instanceof StaticVar) && is_string($node->name) && $this->sandbox->has_whitelist_vars() && !$this->sandbox->allow_variables){
                $this->sandbox->whitelist_var($node->name);
            } else if($node instanceof FuncCall && $node->name instanceof Name && $node->name->toString() == 'define' && !$this->sandbox->is_defined_func('define') && !$this->sandbox->has_blacklist_consts()){
                $name = isset($node->args[0]) ? $node->args[0] : null;
                if($name && $name instanceof Arg && $name->value instanceof String && is_string($name->value->value) && $name->value->value){
                    $this->sandbox->whitelist_const($name->value->value);
                }
            } else if($node instanceof ConstFetch && $node->name instanceof Name && !$this->sandbox->has_blacklist_consts()){
                $this->sandbox->whitelist_const($node->name->toString());
            } else if($node instanceof Class_ && is_string($node->name) && !$this->sandbox->has_blacklist_classes()){
                $this->sandbox->whitelist_class($node->name);
            } else if($node instanceof Interface_ && is_string($node->name) && !$this->sandbox->has_blacklist_interfaces()){
                $this->sandbox->whitelist_interface($node->name);
            } else if($node instanceof Trait_ && is_string($node->name) && !$this->sandbox->has_blacklist_traits()){
                $this->sandbox->whitelist_trait($node->name);
            } else if($node instanceof New_ && $node->class instanceof Name && !$this->sandbox->has_blacklist_types()){
                $this->sandbox->whitelist_type($node->class->toString());
            } else if($node instanceof Global_ && $this->sandbox->has_whitelist_vars()){
                foreach($node->vars as $var){
                    /**
                     * @var Variable    $var
                     */
                    if($var instanceof Variable){
                        $this->sandbox->whitelist_var($var->name);
                    }
                }
            } else if($node instanceof Namespace_){
                if($node->name instanceof Name){
                    $name = $node->name->toString();
                    $this->sandbox->check_namespace($name);
                    if(!$this->sandbox->is_defined_namespace($name)){
                        $this->sandbox->define_namespace($name);
                    }
                }
                return false;
            } else if($node instanceof Use_){
                foreach($node->uses as $use){
                    /**
                     * @var UseUse    $use
                     */
                    if($use instanceof UseUse && $use->name instanceof Name && (is_string($use->alias) || is_null($use->alias))){
                        $name = $use->name->toString();
                        $this->sandbox->check_alias($name);
                        if(!$this->sandbox->is_defined_alias($name)){
                            $this->sandbox->define_alias($name, $use->alias);
                        }
                    }
                }
                return false;
            }
            return null;
        }
    }