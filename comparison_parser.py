import json
import collections
import tatsu
from tatsu.ast import AST

GRAMMAR ="""
# Filter, possibly empty

start
    =
    main:expression $
    ;


expression
    =
    | left:expression bool_op:'&&' ~ right:term
    | left:expression bool_op:'&'  ~ right:term
    | left:expression bool_op:'||' ~ right:term
    | left:expression bool_op:'|'  ~ right:term
    | term
    ;


term
    =
    | left:term comp_op:'>=' ~ right:factor
    | left:term comp_op:'>'  ~ right:factor
    | left:term comp_op:'<=' ~ right:factor
    | left:term comp_op:'<'  ~ right:factor
    | left:term comp_op:'==' ~ right:factor
    | left:term comp_op:'='  ~ right:factor
    | factor
    ;


factor
    =
    | '(' ~ @:expression ')'
    | word
    ;


word = /[a-zA-Z0-9\.\_\-\*]+/;
"""


class NodeMatchSemantics:

    def __init__(self, cpe) -> None:
        self.cpe = cpe

    def word(self, ast):
        return str(ast)

    def term(self, ast):
        if not isinstance(ast, AST):
            return ast
        
        match = {'vulnerable': True,
                  'cpe_name': [],
                   'cpe23Uri': self.cpe
                    }

        if ast.comp_op == '>':
            match["versionStartExcluding"] = ast.right
        elif ast.comp_op == '>=':
            match["versionStartIncluding"] = ast.right
        elif ast.comp_op == '<':
            match["versionEndExcluding"] = ast.right
        elif ast.comp_op == '<=':
            match["versionEndIncluding"] = ast.right
        elif ast.comp_op == '==' or ast.comp_op == '=':
            match["versionEndIncluding"]  = ast.right
            match["versionStartIncluding"] = ast.right
        else:
            raise Exception('Unknown operator', ast.comp_op)
        

        return [ match ]

    def expression(self, ast):
        if not isinstance(ast, AST):
            return ast
        
        # sanity check against syntactically correct expressions that don't make sense
        if not isinstance(ast.left, collections.abc.Sequence) and not isinstance(ast.right, collections.abc.Sequence):
            return {}
        if isinstance(ast.left, str) or isinstance(ast.right, str):
            return {}
        
        node = {"operator": "OR", "children": [], "cpe_match": []}
        if ast.bool_op == '|' or ast.bool_op == '||':
            # if they're both match lists, then just rturn a list of matches
            if isinstance(ast.left, collections.abc.Sequence) and isinstance(ast.right, collections.abc.Sequence):
                return list(ast.left) + list(ast.right)
            else:
                node["cpe_match"].append(ast.left)
                node["cpe_match"].append(ast.right)
                return node
        elif ast.bool_op == '&' or ast.bool_op == '&&':
            
            if isinstance(ast.left, collections.abc.Sequence) and isinstance(ast.right, collections.abc.Sequence) \
                and len(ast.left) == 1 and len(ast.right) == 1:
                #Try to combine the info in right into left
                left, right = ast.left[0], ast.right[0]
                if(("versionStartIncluding" in left or "versionStartExcluding" in left) \
                   and ("versionEndIncluding" in right or "versionEndExcluding" in right) ):
                    if "versionEndIncluding" in right:
                       left["versionEndIncluding"] = right["versionEndIncluding"]
                    elif "versionEndExcluding" in right:
                       left["versionEndExcluding"] = right["versionEndExcluding"]

                    return [left]

            # something failed, so just combine them with an AND node. Less elegant but technically correct
            node["operator"] = "AND"
            node["children"] = [{"operator": "OR", "children": [], "cpe_match": ast.left}, {"operator": "OR", "children": [], "cpe_match": ast.right}]
            return node
        else:
            raise Exception('Unknown operator', ast.bool_op)
        
        return node
    
    def start(self, ast) :
        if not isinstance(ast, AST):
            return ast
        
        if isinstance(ast.main, dict):
            return ast.main
        elif isinstance(ast.main, list) or isinstance(ast.main, tuple):
            # wrap in node since we haven't already
            matches = []
            matches.extend(ast.main) # handle whether it's a list or tuple
            return {"operator": "OR", "children": [], "cpe_match": matches}

parser = tatsu.compile(GRAMMAR)     
def turn_alg_into_nodes(alg_expr, cpe):
    try:
        result = parser.parse(alg_expr, semantics=NodeMatchSemantics(cpe))
        if len(result) > 0:
            return result
    except Exception as e:
        print("Error parsing:" + str(e))

    # base case -- return just the cpe itself as a node  
    return {
                    "operator" : "OR",
                    "children"  : [],
                    "cpe_match" : [
                        {
                            'vulnerable': True,
                            'cpe_name': [],
                            'cpe23Uri': cpe
                        }
                    ],
                    
                }

def main():#
    import pprint
    import json
    from tatsu import parse
    from tatsu.util import asjson

    #parser = tatsu.compile(GRAMMAR)
    # ast = parser.parse('(GRCFND_A < V1200) || (GRCFND_A < V8100) || (GRCPINW < V1100_700) || (GRCPINW < V1100_731) || (GRCPINW < V1200_750)',
    #             semantics=NodeMatchSemantics("cpe:::")
    #             )
    test = "( v > unspecified &&   v < 20.4R3-S8-EVO  ) || ( v > 21.1R1-EVO &&   v < 21.1*  ) || ( v > 21.2 &&   v < 21.2R3-S6-EVO  ) || ( v > 21.3 &&   v < 21.3R3-S5-EVO  ) || ( v > 21.4 &&   v < 21.4R3-S4-EVO  ) || ( v > 22.1 &&   v < 22.1R3-S4-EVO  ) || ( v > 22.2 &&   v < 22.2R3-S2-EVO  ) || ( v > 22.3 &&   v < 22.3R2-S2-EVO  ) || ( v > 22.3 &&   v < 22.3R3-S1-EVO  ) || ( v > 22.4 &&   v < 22.4R2-S1-EVO  ) || ( v > 22.4 &&   v < 22.4R3-EVO  ) || ( v > 23.1 &&   v < 23.1R1-S1-EVO  ) || ( v > 23.1 &&   v < 23.1R2-EVO  )"
    ast = parser.parse(test,
                semantics=NodeMatchSemantics("cpe:::")
                )
    # ast = parser.parse('(version > 11.4 && version < 15.5.7) || (version > 15.6 && version < 15.6.4) || (version > 15.7 && version < 15.7.2)',
    #             semantics=NodeMatchSemantics("cpe:::")
    #             )
    # ast = parser.parse('authenticated_user && access_to_web_interface && can_read_local_files',
    #             semantics=NodeMatchSemantics("cpe:::")
    #             )
    
    #ast = parse(GRAMMAR, '(GRCFND_A < V1200) || (GRCFND_A < V8100) || (GRCPINW < V1100_700) || (GRCPINW < V1100_731) || (GRCPINW < V1200_750)')
    #pprint.pprint(ast, indent=2, width=20)
    print()

    print('JSON')
    print(json.dumps(asjson(ast), indent=2))
    print()


if __name__ == '__main__':
    main()