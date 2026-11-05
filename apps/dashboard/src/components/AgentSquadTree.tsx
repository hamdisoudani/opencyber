import React, { useMemo } from 'react';
import { GitBranch, Terminal, Wrench } from 'lucide-react';
import type { SquadAgentNode, SquadAgentRole } from '../types';

export interface AgentSquadTreeProps {
  agents: SquadAgentNode[];
  onInspectAgent: (agentId: string) => void;
}

interface BuiltAgentTreeNode {
  agent: SquadAgentNode;
  depth: number;
  children: BuiltAgentTreeNode[];
}

export function roleBadgeMeta(role: SquadAgentRole): {
  label: string;
  className: string;
} {
  switch (role) {
    case 'orchestrator':
      return { label: 'LEAD ORCHESTRATOR', className: 'oc-badge oc-badge-cyan mono' };
    case 'recon':
      return { label: 'RECON SCOUT', className: 'oc-badge oc-badge-cyan mono' };
    case 'cartographer':
      return { label: 'CARTOGRAPHER', className: 'oc-badge mono' };
    case 'hypothesis_hunter':
      return { label: 'HYPOTHESIS HUNTER', className: 'oc-badge oc-badge-amber mono' };
    case 'validator':
      return {
        label: 'COUNTEREVIDENCE VALIDATOR',
        className: 'oc-badge oc-badge-emerald mono',
      };
    default:
      return {
        label: String(role).toUpperCase(),
        className: 'oc-badge mono',
      };
  }
}

export function buildAgentHierarchy(
  agents: SquadAgentNode[],
): BuiltAgentTreeNode[] {
  const byId = new Map<string, SquadAgentNode>();
  for (const agent of agents) {
    byId.set(agent.id, agent);
  }

  const childrenMap = new Map<string | null, SquadAgentNode[]>();
  for (const agent of agents) {
    const parentKey =
      agent.parentId && byId.has(agent.parentId) ? agent.parentId : null;
    const list = childrenMap.get(parentKey) ?? [];
    list.push(agent);
    childrenMap.set(parentKey, list);
  }

  const buildBranch = (
    parentKey: string | null,
    depth: number,
  ): BuiltAgentTreeNode[] => {
    const items = childrenMap.get(parentKey) ?? [];
    return items.map((agent) => ({
      agent,
      depth,
      children: buildBranch(agent.id, depth + 1),
    }));
  };

  return buildBranch(null, 1);
}

const AgentSubtreeView: React.FC<{
  node: BuiltAgentTreeNode;
  onInspectAgent: (agentId: string) => void;
}> = ({ node, onInspectAgent }) => {
  const { agent, depth, children } = node;
  const roleMeta = roleBadgeMeta(agent.role);
  const modelTag = agent.provider
    ? `${agent.provider}:${agent.model}`
    : agent.model;

  return (
    <div>
      <button
        type="button"
        id={`agent-node-${agent.id}`}
        className="oc-agent-node-card"
        onClick={() => onInspectAgent(agent.id)}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 6,
            width: '100%',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              minWidth: 0,
            }}
          >
            <span
              className={`oc-status-dot is-${agent.status}${
                agent.status === 'running' ? ' animate-pulse-dot' : ''
              }`}
            />
            <span
              style={{
                fontSize: '12.5px',
                fontWeight: 600,
                color: 'var(--text-primary)',
              }}
              className="truncate"
            >
              {agent.name}
            </span>
          </div>

          <span
            className="mono"
            style={{
              fontSize: '10px',
              color: 'var(--text-muted)',
              flexShrink: 0,
            }}
          >
            L{depth}
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 5,
          }}
        >
          <span className={roleMeta.className} style={{ height: 19, fontSize: '10px' }}>
            {roleMeta.label}
          </span>
          <span
            className="oc-badge mono"
            style={{ height: 19, fontSize: '10px' }}
          >
            {modelTag}
          </span>
        </div>

        <div
          style={{
            fontSize: '11.5px',
            color: 'var(--text-secondary)',
            lineHeight: 1.4,
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden',
          }}
        >
          {agent.task}
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 6,
            marginTop: 2,
            fontSize: '10.5px',
            color: 'var(--text-muted)',
          }}
          className="mono"
        >
          {agent.worktreeBranch ? (
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                minWidth: 0,
              }}
              className="truncate"
            >
              <GitBranch size={11} />
              <span className="truncate">{agent.worktreeBranch}</span>
            </span>
          ) : (
            <span />
          )}

          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
              <Wrench size={10} />
              {agent.toolCallCount}
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
              <Terminal size={10} />
              {agent.messageCount}
            </span>
          </span>
        </div>
      </button>

      {children.length > 0 && (
        <div className="oc-tree-children" role="group">
          {children.map((child) => (
            <AgentSubtreeView
              key={child.agent.id}
              node={child}
              onInspectAgent={onInspectAgent}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export const AgentSquadTree: React.FC<AgentSquadTreeProps> = ({
  agents,
  onInspectAgent,
}) => {
  const hierarchy = useMemo(() => buildAgentHierarchy(agents), [agents]);

  const maxDepth = useMemo(() => {
    const walk = (nodes: BuiltAgentTreeNode[]): number =>
      nodes.reduce(
        (acc, n) => Math.max(acc, n.depth, walk(n.children)),
        0,
      );
    return walk(hierarchy);
  }, [hierarchy]);

  return (
    <div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          marginBottom: 8,
        }}
      >
        <span style={{ fontSize: '12px', fontWeight: 600 }}>
          Agent Squad Hierarchy ({agents.length})
        </span>
        <span className="oc-badge mono" style={{ height: 19, fontSize: '10px' }}>
          {maxDepth}-Tier Tree
        </span>
      </div>

      <div className="oc-tree-root">
        {hierarchy.map((rootNode) => (
          <AgentSubtreeView
            key={rootNode.agent.id}
            node={rootNode}
            onInspectAgent={onInspectAgent}
          />
        ))}
      </div>
    </div>
  );
};
