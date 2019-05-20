"""
    CSharp (С#) domain for sphinx
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Sphinxsharp Pro (with custom styling)

    :copyright: Copyright 2019 by MadTeddy
"""

import re
import warnings

from os import path

from collections import defaultdict, namedtuple

from docutils import nodes
from docutils.parsers.rst import directives, Directive

from sphinx.locale import get_translation
from sphinx.domains import Domain, Index, ObjType
from sphinx.roles import XRefRole
from sphinx.directives import ObjectDescription
from sphinx.util.docfields import DocFieldTransformer
from sphinx.util.nodes import make_refnode
from sphinx import addnodes
from sphinx.util.fileutil import copy_asset

MODIFIERS = ('public', 'private', 'protected', 'internal',
             'static', 'sealed', 'abstract', 'const', 'partial',
             'readonly', 'virtual', 'extern', 'new', 'override',
             'unsafe', 'async', 'event', 'delegate')
VALUE_KEYWORDS = ('char', 'ulong', 'byte', 'decimal',
                  'double', 'bool', 'int', 'null', 'sbyte',
                  'float', 'long', 'object', 'short', 'string',
                  'uint', 'ushort', 'void')
PARAM_MODIFIERS = ('ref', 'out', 'params')

MODIFIERS_RE = '|'.join(MODIFIERS)
PARAM_MODIFIERS_RE = '|'.join(PARAM_MODIFIERS)

TYPE_SIG_RE = re.compile(r'^((?:(?:' + MODIFIERS_RE
                         + r')\s+)*)?(\w+)\s([\w\.]+)(?:<(.+)>)?(?:\s?\:\s?(.+))?$')
REF_TYPE_RE = re.compile(r'^(?:(new)\s+)?([\w\.]+)\s*(?:<(.+)>)*(\[\])*\s?(?:\((.*)\))?$')
METHOD_SIG_RE = re.compile(r'^((?:(?:' + MODIFIERS_RE
                           + r')\s+)*)?([^\s=\(\)]+\s+)?([^\s=\(\)]+)\s?(?:\<(.+)\>)?\s?(?:\((.+)*\))$')
PARAM_SIG_RE = re.compile(r'^(?:(?:(' + PARAM_MODIFIERS_RE + r')\s)*)?([^=]+)\s+([^=]+)\s*(?:=\s?(.+))?$')
VAR_SIG_RE = re.compile(r'^((?:(?:' + MODIFIERS_RE + r')\s+)*)?([^=]+)\s+([^\s=]+)\s*(?:=\s*(.+))?$')
PROP_SIG_RE = re.compile(r'^((?:(?:' + MODIFIERS_RE
                         + r')\s+)*)?(.+)\s+([^\s]+)\s*(?:{(\s*get;\s*)?((?:'
                         + MODIFIERS_RE + r')?\s*set;\s*)?})$')
ENUM_SIG_RE = re.compile(r'^((?:(?:' + MODIFIERS_RE + r')\s+)*)?(?:enum)\s?(\w+)$')

_ = get_translation('sphinxsharp')


class CSharpObject(ObjectDescription):
    PARENT_ATTR_NAME = 'sphinxsharp:parent'
    PARENT_TYPE_NAME = 'sphinxsharp:type'

    ParentType = namedtuple('ParentType', ['parent', 'name', 'type', 'override'])

    option_spec = {
        'noindex': directives.flag
    }

    def __init__(self, *args, **kwargs):
        super(CSharpObject, self).__init__(*args, **kwargs)
        self.parentname_set = None
        self.parentname_saved = None

    def run(self):
        if ':' in self.name:
            self.domain, self.objtype = self.name.split(':', 1)
        else:
            self.domain, self.objtype = '', self.name
        self.indexnode = addnodes.index(entries=[])

        node = addnodes.desc()
        node.document = self.state.document
        node['domain'] = self.domain

        node['classes'].append('csharp')

        node['objtype'] = node['desctype'] = self.objtype
        node['noindex'] = noindex = ('noindex' in self.options)

        self.names = []
        signatures = self.get_signatures()
        for i, sig in enumerate(signatures):
            beforesignode = CSNodes.EmptyNode()
            node.append(beforesignode)

            signode = addnodes.desc_signature(sig, '')
            signode['first'] = False
            node.append(signode)
            self.before_sig(beforesignode)
            try:
                name = self.handle_signature(sig, signode)
            except ValueError:
                signode.clear()
                signode += addnodes.desc_name(sig, sig)
                continue
            if name not in self.names:
                self.names.append(name)
                if not noindex:
                    self.add_target_and_index(name, sig, signode)

            aftersignode = CSNodes.EmptyNode()
            node.append(aftersignode)
            self.after_sig(aftersignode)

        contentnode = addnodes.desc_content()
        node.append(contentnode)
        self.before_content_node(contentnode)
        if self.names:
            self.env.temp_data['object'] = self.names[0]
        self.before_content()
        self.state.nested_parse(self.content, self.content_offset, contentnode)
        self.after_content_node(contentnode)
        DocFieldTransformer(self).transform_all(contentnode)
        self.env.temp_data['object'] = None
        self.after_content()
        return [self.indexnode, node]

    def before_sig(self, signode):
        """
        Called before main ``signode`` appends
        """
        pass

    def after_sig(self, signode):
        """
        Called after main ``signode`` appends
        """
        pass

    def before_content_node(self, node):
        """
        Get ``contentnode`` before main content will append
        """
        pass

    def after_content_node(self, node):
        """
        Get ``contentnode`` after main content was appended
        """
        pass

    def before_content(self):
        obj = self.env.temp_data['object']
        if obj:
            self.parentname_set = True
            self.parentname_saved = self.env.ref_context.get(self.PARENT_ATTR_NAME)
            self.env.ref_context[self.PARENT_ATTR_NAME] = obj
        else:
            self.parentname_set = False

    def after_content(self):
        if self.parentname_set:
            self.env.ref_context[self.PARENT_ATTR_NAME] = self.parentname_saved

    def has_parent(self):
        return self._check_parent(self.PARENT_ATTR_NAME)

    def has_parent_type(self):
        return self._check_parent(self.PARENT_TYPE_NAME)

    def _check_parent(self, attr):
        return attr in self.env.ref_context and \
               self.env.ref_context[attr] is not None

    def get_parent(self):
        return self.env.ref_context.get(self.PARENT_ATTR_NAME)

    def get_type_parent(self):
        return self.env.ref_context.get(self.PARENT_TYPE_NAME)

    def get_index_text(self, sig, name, typ):
        raise NotImplementedError('Must be implemented in subclass')

    def parse_signature(self, sig):
        raise NotImplementedError('Must be implemented in subclass')

    def add_target_and_index(self, name, sig, signode):
        objname, objtype = self.get_obj_name(sig)
        type_parent = self.get_type_parent() if self.has_parent_type() else None
        if self.objtype != 'type' and type_parent:
            self.env.ref_context[self.PARENT_ATTR_NAME] = '{}{}'.format(type_parent.parent + '.' \
                                                                         if type_parent.parent else '',
                                                                        type_parent.name)
            name = self.get_fullname(objname)
            self.names.clear()
            self.names.append(name)
        anchor = '{}-{}'.format(self.objtype, name)
        if anchor not in self.state.document.ids:
            signode['names'].append(anchor)
            signode['ids'].append(anchor)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['sphinxsharp']['objects']
            key = (self.objtype, name)
            if key in objects:
                warnings.warn('duplicate description of {}, other instance in {}'.format(
                    key, self.env.doc2path(objects[key][0])), Warning)
            objects[key] = (self.env.docname, 'delegate' if self.objtype == 'method' else objtype)
        index_text = self.get_index_text(sig, objname, objtype)
        if index_text:
            parent = self.get_parent() if self.has_parent() else None
            if type_parent and type_parent.override and type_parent.name != objname:
                type_parent = self.ParentType(parent=type_parent.parent, name=type_parent.name, type=type_parent.type,
                                              override=None)
            index_format = '{parent} (C# {namespace});{text}' \
                if (type_parent and type_parent.parent and (type_parent.name == objname and self.objtype == 'type') \
                    and not type_parent.override) or (parent and not type_parent) \
                else '{name} (C# {type} {in_text} {parent});{text}' if type_parent and type_parent.name else '{text}'
            self.indexnode['entries'].append(('single', index_format.format(
                parent=type_parent.parent if type_parent else parent if parent else '',
                namespace=_('namespace'),
                text=index_text,
                name=type_parent.override if type_parent and type_parent.override \
                else type_parent.name if type_parent else '',
                type=_(type_parent.type) if type_parent else '',
                in_text=_('in')
            ), anchor, None, None))

    def get_fullname(self, name):
        fullname = '{parent}{name}'.format(
            parent=self.get_parent() + '.' if self.has_parent() else '', name=name)
        return fullname

    def get_obj_name(self, sig):
        raise NotImplementedError('Must be implemented in subclass')

    def append_ref_signature(self, typname, signode, append_generic=True):
        match = REF_TYPE_RE.match(typname.strip())
        if not match:
            raise Exception('Invalid reference type signature. Got: {}'.format(typname))
        is_new, name, generic, is_array, constr = match.groups()
        tnode = addnodes.desc_type()
        if is_new:
            tnode += CSNodes.Keyword(text='new')
            tnode += CSNodes.TextNode(text=' ')
        types = name.split('.')
        explicit_path = []
        i = 1
        for t in types:
            styp = t.strip()
            refnode = None
            if styp not in VALUE_KEYWORDS:
                explicit_path.append(styp)
                refnode = addnodes.pending_xref('', refdomain='sphinxsharp', reftype=None,
                                                            reftarget=styp, modname=None, classname=None)
                if not self.has_parent():
                    refnode[self.PARENT_ATTR_NAME] = None
                else:
                    refnode[self.PARENT_ATTR_NAME] = self.get_parent()
                if len(explicit_path) > 1:
                    target_path = '.'.join(explicit_path[:-1])
                    type_par = self.get_type_parent() if self.has_parent_type() else None
                    refnode[self.PARENT_ATTR_NAME] = (type_par.parent + '.' \
                                                        if type_par and type_par.parent \
                                                        else '') + target_path
                refnode += CSNodes.UnknownType(typ=None, text=styp)
            else:
                refnode = CSNodes.Keyword(text=styp)
            tnode += refnode
            if i < len(types):
                tnode += CSNodes.TextNode(text='.')
                i += 1
        if append_generic and generic:
            gnode = CSNodes.EmptyNode()
            gnode += CSNodes.TextNode(text='<')
            gen_groups = split_sig(generic)
            i = 1
            for g in gen_groups:
                self.append_ref_signature(g, gnode, append_generic)
                if i < len(gen_groups):
                    gnode += CSNodes.TextNode(text=', ')
                    i += 1
            gnode += CSNodes.TextNode(text='>')
            tnode += gnode
        if is_array:
            tnode += CSNodes.TextNode(text='[]')
        if constr is not None:
            tnode += CSNodes.TextNode(text='()')
        signode += tnode

    def append_generic(self, generic, signode):
        gnode = CSNodes.EmptyNode()
        gnode += CSNodes.TextNode(text='<')
        generics = generic.split(',')
        i = 1
        for g in generics:
            gnode += CSNodes.Generic(text=g)
            if i < len(generics):
                gnode += CSNodes.TextNode(text=', ')
                i += 1
        gnode += CSNodes.TextNode(text='>')
        signode += gnode


class CSharpType(CSharpObject):
    option_spec = {
        **CSharpObject.option_spec,
        'nonamespace': directives.flag,
        'parent': directives.unchanged
    }

    def before_sig(self, signode):
        if 'nonamespace' not in self.options and self.has_parent():
            signode += CSNodes.Description(title=_('namespace'), desc=self.get_parent())

    def handle_signature(self, sig, signode):
        mod, typ, name, generic, inherits = self.parse_signature(sig)
        tnode = CSNodes.EmptyNode()
        tnode += CSNodes.Modificator(text='{}'.format(mod if mod else 'private'))
        tnode += CSNodes.TextNode(text=' ')
        tnode += CSNodes.Keyword(text='{}'.format(typ))
        tnode += CSNodes.TextNode(text=' ')
        tnode += CSNodes.UnknownType(typ=typ, text=name)
        if generic:
            self.append_generic(generic, tnode)
        if inherits:
            inherits_node = CSNodes.EmptyNode()
            inherits_node += CSNodes.TextNode(text=' : ')

            inherit_types = split_sig(inherits)
            i = 1
            for t in inherit_types:
                self.append_ref_signature(t, inherits_node)
                if i < len(inherit_types):
                    inherits_node += CSNodes.TextNode(text=', ')
                    i += 1
            tnode += inherits_node
        signode += tnode

        opt_parent = self.options['parent'] if 'parent' in self.options else None
        form = '{}.{}' if self.has_parent() and opt_parent else '{}{}'
        parent = form.format(self.get_parent() if self.has_parent() else '', opt_parent if opt_parent else '')
        self.env.ref_context[CSharpObject.PARENT_TYPE_NAME] = self.ParentType(
            parent=parent, name=name, type=typ, override=opt_parent)
        if opt_parent:
            self.env.ref_context[self.PARENT_ATTR_NAME] = parent
        return self.get_fullname(name)

    def get_index_text(self, sig, name, typ):
        rname = '{} (C# {})'.format(name, _(typ))
        return rname

    def parse_signature(self, sig):
        match = TYPE_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid type signature. Got: {}'.format(sig))
        mod, typ, names, generic, inherits = match.groups()
        return mod, typ.strip(), names, generic, inherits

    def get_obj_name(self, sig):
        _, typ, name, _, _ = self.parse_signature(sig)
        return name, typ


class CSharpEnum(CSharpObject):
    option_spec = {**CSharpObject.option_spec, 'values': directives.unchanged_required,
                   **dict(zip([('val(' + str(i) + ')') for i in range(1, 21)],
                              [directives.unchanged] * 20))}

    def handle_signature(self, sig, signode):
        mod, name = self.parse_signature(sig)
        node = CSNodes.EmptyNode()
        if mod:
            node += CSNodes.Modificator(text='{}'.format(mod.strip()))
            node += CSNodes.TextNode(text=' ')
        node += CSNodes.Keyword(text='enum')
        node += CSNodes.TextNode(text=' ')
        node += CSNodes.Enum(text='{}'.format(name.strip()))
        signode += node
        return self.get_fullname(name)

    def after_content_node(self, node):
        options = self.options['values'].split()
        node += CSNodes.Description(title=_('values').title(), desc=', '.join(options))
        options_values = list(value for key, value in self.options.items() \
                              if key not in ('noindex', 'values') and value)
        if not options_values:
            return
        i = 0
        for vname in options:
            if i < len(options_values):
                node += CSNodes.Description(title=vname, desc=options_values[i])
                i += 1

    def parse_signature(self, sig):
        match = ENUM_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid enum signature. Got: {}'.format(sig))
        mod, name = match.groups()
        return mod, name.strip()

    def get_index_text(self, sig, name, typ):
        rname = '{} (C# {})'.format(name, _('enum'))
        return rname

    def get_obj_name(self, sig):
        _, name = self.parse_signature(sig)
        return name, 'enum'


class CSharpVariable(CSharpObject):

    _default = ''

    def handle_signature(self, sig, signode):
        mod, typ, name, self._default = self.parse_signature(sig)
        node = CSNodes.EmptyNode()
        node += CSNodes.Modificator(text='{}'.format(mod if mod else 'private'))
        node += CSNodes.TextNode(text=' ')
        self.append_ref_signature(typ, node)
        node += CSNodes.TextNode(text=' ')
        node += CSNodes.VariableName(text='{}'.format(name))
        signode += node
        return self.get_fullname(name)

    def before_content_node(self, node):
        if self._default:
            node += CSNodes.Description(title=_('value').title(), desc=self._default)

    def parse_signature(self, sig):
        match = VAR_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid variable signature. Got: {}'.format(sig))
        mod, typ, name, default = match.groups()
        return mod, typ.strip(), name.strip(), default

    def get_index_text(self, sig, name, typ):
        rname = '{} (C# {})->{}'.format(name, _('variable'), typ)
        return rname

    def get_obj_name(self, sig):
        _, typ, name, _ = self.parse_signature(sig)
        return name, typ


class CSharpProperty(CSharpObject):

    def handle_signature(self, sig, signode):
        mod, typ, name, getter, setter = self.parse_signature(sig)
        node = CSNodes.EmptyNode()
        node += CSNodes.Modificator(text='{}'.format(mod if mod else 'private'))
        node += CSNodes.TextNode(text=' ')
        self.append_ref_signature(typ, node)
        node += CSNodes.TextNode(text=' ')
        node += CSNodes.MethodName(text='{}'.format(name))
        node += CSNodes.TextNode(text=' { ')
        accessors = []
        if getter:
            accessors.append('get;')
        if setter:
            accessors.append(setter.strip())
        node += CSNodes.Modificator(text=' '.join(accessors))
        node += CSNodes.TextNode(text=' } ')
        signode += node
        return self.get_fullname(name)

    def parse_signature(self, sig):
        match = PROP_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid property signature. Got: {}'.format(sig))
        mod, typ, name, getter, setter = match.groups()
        return mod, typ.strip(), name.strip(), getter, setter

    def get_index_text(self, sig, name, typ):
        rname = '{} (C# {})->{}'.format(name, _('property'), typ)
        return rname

    def get_obj_name(self, sig):
        _, typ, name, _, _ = self.parse_signature(sig)
        return name, typ


class CSharpMethod(CSharpObject):
    option_spec = {**CSharpObject.option_spec,
                    'returns': directives.unchanged,
                   **dict(zip([('param(' + str(i) + ')') for i in range(1, 8)],
                              [directives.unchanged] * 7))}

    _params_list = ()

    def handle_signature(self, sig, signode):
        mod, typ, name, generic, params = self.parse_signature(sig)
        node = CSNodes.EmptyNode()
        node += CSNodes.Modificator(text='{}'.format(mod if mod else 'private'))
        node += CSNodes.TextNode(text=' ')
        self.append_ref_signature(typ if typ else name, node)
        if typ:
            node += CSNodes.TextNode(text=' ')
            node += CSNodes.MethodName(text='{}'.format(name))
        if generic:
            self.append_generic(generic, node)
        param_node = CSNodes.EmptyNode()
        param_node += CSNodes.TextNode(text='(')
        if params:
            self._params_list = self._get_params(params)
            i = 1
            for (pmod, ptyp, pname, pvalue) in self._params_list:
                pnode = CSNodes.EmptyNode()
                if pmod:
                    pnode += CSNodes.Keyword(text='{}'.format(pmod))
                    pnode += CSNodes.TextNode(text=' ')
                self.append_ref_signature(ptyp, pnode)
                pnode += CSNodes.TextNode(text=' ')
                pnode += CSNodes.TextNode(text='{}'.format(pname))
                if pvalue:
                    pnode += CSNodes.TextNode(text=' = ')
                    self.append_ref_signature(pvalue, pnode)
                param_node += pnode
                if i < len(self._params_list):
                    param_node += CSNodes.TextNode(text=', ')
                    i += 1
        param_node += CSNodes.TextNode(text=')')
        node += param_node
        signode += node
        return self.get_fullname(name)

    def before_content_node(self, node):
        if 'returns' in self.options:
            node += CSNodes.Description(title=_('returns').title(), desc=self.options['returns'])

    def after_content_node(self, node):
        options_values = list(value for key, value in self.options.items() if key != 'noindex')
        i = 0
        for (_, _, pname, _) in self._params_list:
            if i < len(options_values):
                node += CSNodes.Description(title=pname, desc=options_values[i], lower=True)
                i += 1

    def after_content(self):
        super().after_content()
        if self._params_list is not None and len(self._params_list) > 0:
            del self._params_list

    def parse_signature(self, sig):
        match = METHOD_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid method signature. Got: {}'.format(sig))
        mod, typ, name, generic, params = match.groups()
        return mod, typ, name.strip(), generic, params

    @staticmethod
    def parse_param_signature(sig):
        match = PARAM_SIG_RE.match(sig.strip())
        if not match:
            raise Exception('Invalid parameter signature. Got: {}'.format(sig))
        mod, typ, name, value = match.groups()
        return mod, typ.strip(), name.strip(), value

    def _get_params(self, params):
        if not params:
            return None
        result = []
        params_group = split_sig(params)
        for param in params_group:
            pmod, ptyp, pname, pvalue = self.parse_param_signature(param)
            result.append((pmod, ptyp, pname, pvalue))
        return result

    def get_index_text(self, sig, name, typ):
        params_text = ''
        if self._params_list:
            names = [pname
                     for _, _, pname, _
                     in self._params_list]
            params_text = '({})'.format(', '.join(names))
        if typ:
            rname = '{}{} (C# {})->{}'.format(name, params_text, _('method'), typ)
        else:
            rname = '{}{} (C# {})->{}'.format(name, params_text, _('constructor'), name)
        return rname

    def get_obj_name(self, sig):
        _, typ, name, _, _ = self.parse_signature(sig)
        return name, typ


class CSharpNamespace(Directive):
    required_arguments = 1

    def run(self):
        env = self.state.document.settings.env
        namespace = self.arguments[0].strip()
        if namespace is None:
            env.ref_context.pop(CSharpObject.PARENT_ATTR_NAME, None)
        else:
            env.ref_context[CSharpObject.PARENT_ATTR_NAME] = namespace
        return []


class CSharpEndType(Directive):
    required_arguments = 0

    def run(self):
        env = self.state.document.settings.env
        if CSharpObject.PARENT_TYPE_NAME in env.ref_context:
            env.ref_context.pop(CSharpObject.PARENT_TYPE_NAME, None)
        return []


class CSharpXRefRole(XRefRole):
    def process_link(self, env, refnode, has_explicit_title, title, target):
        refnode[CSharpObject.PARENT_ATTR_NAME] = env.ref_context.get(
            CSharpObject.PARENT_ATTR_NAME)
        return super(CSharpXRefRole, self).process_link(env, refnode,
                                                        has_explicit_title, title, target)


class CSharpIndex(Index):
    name = 'csharp'
    localname = 'CSharp Index'
    shortname = 'CSharp'

    def generate(self, docnames=None):
        content = defaultdict(list)

        objects = self.domain.get_objects()
        objects = sorted(objects, key=lambda obj: obj[0])

        for name, dispname, objtype, docname, anchor, _ in objects:
            content[dispname.split('.')[-1][0].lower()].append(
                (dispname, 0, docname, anchor, docname, '', objtype))

        content = sorted(content.items())

        return content, True


class CSharpDomain(Domain):
    name = 'sphinxsharp'
    label = 'C#'

    roles = {
        'type': CSharpXRefRole(),
        'var': CSharpXRefRole(),
        'prop': CSharpXRefRole(),
        'meth': CSharpXRefRole(),
        'enum': CSharpXRefRole()
    }

    object_types = {
        'type': ObjType(_('type'), 'type', 'obj'),
        'variable': ObjType(_('variable'), 'var', 'obj'),
        'property': ObjType(_('property'), 'prop', 'obj'),
        'method': ObjType(_('method'), 'meth', 'obj'),
        'enum': ObjType(_('enum'), 'enum', 'obj')
    }

    directives = {
        'namespace': CSharpNamespace,
        'end-type': CSharpEndType,
        'type': CSharpType,
        'variable': CSharpVariable,
        'property': CSharpProperty,
        'method': CSharpMethod,
        'enum': CSharpEnum
    }

    indices = {
        CSharpIndex
    }

    initial_data = {
        'objects': {}  # (objtype, name) -> (docname, objtype(class, struct etc.))
    }

    def clear_doc(self, docname):
        for (objtype, name), (doc, _) in self.data['objects'].copy().items():
            if doc == docname:
                del self.data['objects'][(objtype, name)]

    def get_objects(self):
        for (objtype, name), (docname, _) in self.data['objects'].items():
            yield (name, name, objtype, docname, '{}-{}'.format(objtype, name), 0)

    def resolve_xref(self, env, fromdocname, builder,
                     typ, target, node, contnode):
        targets = get_targets(target, node)

        objects = self.data['objects']
        roletypes = self.objtypes_for_role(typ)

        types = ('type', 'enum', 'method') if typ is None else roletypes

        for t in targets:
            for objtyp in types:
                key = (objtyp, t)
                if key in objects:
                    obj = objects[key]
                    if typ is not None: 
                        role = self.role_for_objtype(objtyp)
                        node['reftype'] = role
                    else:
                        contnode = CSNodes.UnknownType(typ=obj[1], text=target)
                    return make_refnode(builder, fromdocname, obj[0],
                                        '{}-{}'.format(objtyp, t), contnode,
                                        '{} {}'.format(obj[1], t))
        if typ is None:
            contnode = CSNodes.UnknownType(text=target)
        return None

    def merge_domaindata(self, docnames, otherdata):
        for (objtype, name), (docname, typ) in otherdata['objects'].items():
            if docname in docnames:
                self.data['objects'][(objtype, name)] = (docname, typ)

    def resolve_any_xref(self, env, fromdocname, builder, target, node, contnode):
        for typ in self.roles:
            xref = self.resolve_xref(env, fromdocname, builder, typ,
                                     target, node, contnode)
            if xref:
                return [('sphinxsharp:{}'.format(typ), xref)]

        return []


class CSNodes:
    _TYPES = ('class', 'struct', 'interface', 'enum', 'delegate')

    class BaseNode(nodes.Element):

        def __init__(self, rawsource='', *children, **attributes):
            super().__init__(rawsource, *children, **attributes)

        @staticmethod
        def visit_html(self, node):
            self.body.append(self.starttag(node, 'div'))

        @staticmethod
        def depart_html(self, node):
            self.body.append('</div>')

    class EmptyNode(BaseNode):

        def __init__(self, rawsource='', *children, **attributes):
            super().__init__(rawsource, *children, **attributes)

        @staticmethod
        def visit_html(self, node): pass

        @staticmethod
        def depart_html(self, node): pass

    class InlineText(BaseNode):

        def __init__(self, rawsource, type_class, text, *children, **attributes):
            super().__init__(rawsource, *children, **attributes)
            if type_class is None:
                return
            self['classes'].append(type_class)
            if text:
                self.append(nodes.raw(text=text, format='html'))

        @staticmethod
        def visit_html(self, node):
            self.body.append(self.starttag(node, 'span').replace('\n', ''))

        @staticmethod
        def depart_html(self, node):
            self.body.append('</span>')

    class Description(BaseNode):

        def __init__(self, rawsource='', title='', desc='', *children, **attributes):
            super().__init__(rawsource, *children, **attributes)
            self['classes'].append('desc')
            if title and desc:
                if 'lower' not in attributes:
                    title = title[0].upper() + title[1:]
                node = nodes.raw(
                    text='<strong class="first">{}:</strong><span class="last">{}</span>'.format(title, desc),
                    format='html')
                self.append(node)
            else:
                raise Exception('Title and description must be assigned.')

    class Modificator(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'mod', text, *children, **attributes)

    class UnknownType(InlineText):

        def __init__(self, rawsource='', typ='', text='', *children, **attributes):
            objclass = typ
            if not text:
                super().__init__(rawsource, None, text, *children, **attributes)
                return
            if typ not in CSNodes._TYPES:
                objclass = 'kw'
                if typ not in VALUE_KEYWORDS:
                    objclass = 'unknown'
            super().__init__(rawsource, objclass, text, *children, **attributes)

    class TextNode(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'text', text, *children, **attributes)

    class MethodName(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'meth-name', text, *children, **attributes)

    class VariableName(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'var-name', text, *children, **attributes)

    class Keyword(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'kw', text, *children, **attributes)

    class Enum(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'enum', text, *children, **attributes)

    class Generic(InlineText):

        def __init__(self, rawsource='', text='', *children, **attributes):
            super().__init__(rawsource, 'generic', text, *children, **attributes)

    @staticmethod
    def add_nodes(app):
        app.add_node(CSNodes.Description,
                     html=(CSNodes.Description.visit_html, CSNodes.Description.depart_html))
        app.add_node(CSNodes.Modificator,
                     html=(CSNodes.Modificator.visit_html, CSNodes.Modificator.depart_html))
        app.add_node(CSNodes.UnknownType,
                     html=(CSNodes.UnknownType.visit_html, CSNodes.UnknownType.depart_html))
        app.add_node(CSNodes.TextNode,
                     html=(CSNodes.TextNode.visit_html, CSNodes.TextNode.depart_html))
        app.add_node(CSNodes.Enum,
                     html=(CSNodes.Enum.visit_html, CSNodes.Enum.depart_html))
        app.add_node(CSNodes.Keyword,
                     html=(CSNodes.Keyword.visit_html, CSNodes.Keyword.depart_html))
        app.add_node(CSNodes.MethodName,
                     html=(CSNodes.MethodName.visit_html, CSNodes.MethodName.depart_html))
        app.add_node(CSNodes.VariableName,
                     html=(CSNodes.VariableName.visit_html, CSNodes.VariableName.depart_html))
        app.add_node(CSNodes.BaseNode,
                     html=(CSNodes.BaseNode.visit_html, CSNodes.BaseNode.depart_html))
        app.add_node(CSNodes.EmptyNode,
                     html=(CSNodes.EmptyNode.visit_html, CSNodes.EmptyNode.depart_html))
        app.add_node(CSNodes.Generic,
                     html=(CSNodes.Generic.visit_html, CSNodes.Generic.depart_html))


def split_sig(params):
    if not params:
        return None
    result = []
    current = ''
    level = 0
    for char in params:
        if char in ('<', '{', '['):
            level += 1
        elif char in ('>', '}', ']'):
            level -= 1
        if char != ',' or level > 0:
            current += char
        elif char == ',' and level == 0:
            result.append(current)
            current = ''
    if current.strip() != '':
        result.append(current)
    return result

def get_targets(target, node):
    targets = [target]
    if node[CSharpObject.PARENT_ATTR_NAME] is not None:
        parts = node[CSharpObject.PARENT_ATTR_NAME].split('.')
        while parts:
            targets.append('{}.{}'.format('.'.join(parts), target))
            parts = parts[:-1]
    return targets

def copy_asset_files(app, exc):
    package_dir = path.abspath(path.dirname(__file__))
    asset_files = [path.join(package_dir, '_static/css/sphinxsharp.css')]
    if exc is None:  # build succeeded 
        for asset_path in asset_files:
            copy_asset(asset_path, path.join(app.outdir, '_static'))

def setup(app):
    app.connect('build-finished', copy_asset_files)
    package_dir = path.abspath(path.dirname(__file__))

    app.add_domain(CSharpDomain)
    app.add_stylesheet('sphinxsharp.css')
    override_file = path.join(app.confdir, '_static/sphinxsharp-override.css')
    if path.exists(override_file):
        app.add_stylesheet('sphinxsharp-override.css')
    CSNodes.add_nodes(app)

    locale_dir = path.join(package_dir, 'locales')
    app.add_message_catalog('sphinxsharp', locale_dir)
    return {
        'version': '1.0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
