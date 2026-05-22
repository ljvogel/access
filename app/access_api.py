import copy
import glob
import importlib.util
import os
import sys
from types import SimpleNamespace
from uuid import uuid4

from aiohttp import web
from aiohttp_jinja2 import template

from app.objects.c_ability import Ability
from app.objects.secondclass.c_executor import Executor
from app.objects.secondclass.c_fact import Fact
from app.service.auth_svc import for_all_public_methods, check_authorization

_PARSER_SIGNALS_FAILURE = 418


def _load_parser_fresh(path):
    name = '_access_debug_parser'
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@for_all_public_methods(check_authorization)
class AccessApi:

    def __init__(self, services):
        self.data_svc = services.get('data_svc')
        self.rest_svc = services.get('rest_svc')
        self.auth_svc = services.get('auth_svc')

    @template('access.html')
    async def landing(self, request):
        search = dict(access=tuple(await self.auth_svc.get_permissions(request)))
        abilities = await self.data_svc.locate('abilities', match=search)
        tactics = sorted(list(set(a.tactic.lower() for a in abilities)))
        obfuscators = [o.display for o in await self.data_svc.locate('obfuscators')]
        return dict(agents=[a.display for a in await self.data_svc.locate('agents', match=search)],
                    abilities=[a.display for a in abilities], tactics=tactics, obfuscators=obfuscators)

    async def exploit(self, request):
        data = await request.json()
        converted_facts = [Fact(trait=f['trait'], value=f['value']) for f in data.get('facts', [])]
        await self.rest_svc.task_agent_with_ability(data['paw'], data['ability_id'], data['obfuscator'], converted_facts)
        return web.json_response('complete')

    async def abilities(self, request):
        data = await request.json()
        agent_search = dict(access=tuple(await self.auth_svc.get_permissions(request)), paw=data['paw'])
        agent = (await self.data_svc.locate('agents', match=agent_search))[0]
        ability_search = dict(access=tuple(await self.auth_svc.get_permissions(request)))
        abilities = await self.data_svc.locate('abilities', match=ability_search)
        capable_abilities = await agent.capabilities(list(abilities))
        return web.json_response([a.display for a in capable_abilities])

    async def executor(self, request):
        data = await request.json()
        agent_search = dict(access=tuple(await self.auth_svc.get_permissions(request)), paw=data['paw'])
        agent = (await self.data_svc.locate('agents', match=agent_search))[0]
        ability_search = dict(access=tuple(await self.auth_svc.get_permissions(request)), ability_id=data['ability_id'])
        ability = (await self.data_svc.locate('abilities', match=ability_search))[0]
        executor = await agent.get_preferred_executor(ability)
        if not executor:
            return web.json_response(dict(error='Executor not found for ability'))
        trimmed_ability = copy.deepcopy(ability)
        trimmed_ability.remove_all_executors()
        trimmed_ability.add_executor(executor)
        return web.json_response(trimmed_ability.display)

    async def execute(self, request):
        data = await request.json()
        agent_search = dict(access=tuple(await self.auth_svc.get_permissions(request)), paw=data['paw'])
        agent = (await self.data_svc.locate('agents', match=agent_search))[0]
        executor = Executor(name=data['executor'], platform=agent.platform,
                            command=data['command'], timeout=60)
        ability = Ability(ability_id=str(uuid4()), name='Ad-hoc command', description='',
                          tactic='debug', technique_id='T0000', technique_name='Ad-hoc')
        ability.add_executor(executor)
        await agent.task(abilities=[ability], obfuscator=data.get('obfuscator', 'plain-text'), facts=[])
        return web.json_response('complete')

    async def parse(self, request):
        data = await request.json()
        parser_path = data.get('parser_path', '')
        output = data.get('output', '')
        mappers_raw = data.get('mappers', [])

        if not os.path.isfile(parser_path):
            return web.json_response({'error': f'File not found: {parser_path}'}, status=400)

        try:
            module = _load_parser_fresh(parser_path)
            mappers = [SimpleNamespace(source=m.get('source', ''), edge=m.get('edge', ''),
                                       target=m.get('target', '')) for m in mappers_raw]
            parser_info = dict(module=parser_path, used_facts=[], mappers=mappers, source_facts=[])
            parser = module.Parser(parser_info)
            relationships = parser.parse(output)
        except Exception as exc:
            return web.json_response({'error': str(exc)}, status=400)

        results = []
        for r in relationships:
            if r == _PARSER_SIGNALS_FAILURE:
                continue
            results.append(dict(
                source=dict(trait=r.source.trait, value=str(r.source.value)),
                edge=r.edge,
                target=dict(trait=r.target.trait, value=str(r.target.value)) if r.target else None
            ))
        return web.json_response({'relationships': results})

    async def get_parsers(self, request):
        return web.json_response({'groups': self._discover_parsers()})

    @staticmethod
    def _discover_parsers():
        root = os.getcwd()
        pattern = os.path.join(root, 'plugins', '*', 'app', 'parsers', '*.py')
        groups = {}
        for path in sorted(glob.glob(pattern)):
            if os.path.basename(path) == '__init__.py':
                continue
            plugin_name = os.path.relpath(path, root).split(os.sep)[1]
            parser_name = os.path.basename(path)[:-3]
            groups.setdefault(plugin_name, []).append({'name': parser_name, 'path': path})
        return [{'plugin': p, 'parsers': groups[p]} for p in sorted(groups)]
