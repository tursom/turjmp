<template>
  <el-tree
    :data="treeData"
    node-key="key"
    :props="{ label: 'label', children: 'children' }"
    :default-expand-all="autoExpand"
    highlight-current
    @node-click="onNodeClick"
  >
    <template #default="{ data }">
      <span class="tree-node" :class="{ 'is-asset': data.type === 'asset' }">
        <el-icon v-if="data.type === 'node'" class="node-icon">
          <Folder />
        </el-icon>
        <el-icon v-else class="asset-icon">
          <Monitor />
        </el-icon>
        <span>{{ data.label }}</span>
      </span>
    </template>
  </el-tree>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Folder, Monitor } from '@element-plus/icons-vue'
import type { Node, AssetWithPlatform } from '@/types'

const props = withDefaults(
  defineProps<{
    nodes: Node[]
    assets: AssetWithPlatform[]
    autoExpand?: boolean
  }>(),
  {
    autoExpand: true,
  },
)

const emit = defineEmits<{
  'node-click': [payload: { type: 'node' | 'asset'; data: Node | AssetWithPlatform }]
}>()

interface TreeNodeData {
  key: string
  label: string
  type: 'node' | 'asset'
  children?: TreeNodeData[]
  rawData: Node | AssetWithPlatform
}

const treeData = computed(() => {
  const nodeMap = new Map<number, TreeNodeData>()
  const roots: TreeNodeData[] = []

  // Create node entries
  for (const n of props.nodes) {
    const tn: TreeNodeData = {
      key: `node-${n.id}`,
      label: n.name,
      type: 'node',
      children: [],
      rawData: n,
    }
    nodeMap.set(n.id, tn)
  }

  // Link children to parents
  for (const n of props.nodes) {
    const tn = nodeMap.get(n.id)!
    if (n.parent_id != null && nodeMap.has(n.parent_id)) {
      nodeMap.get(n.parent_id)!.children!.push(tn)
    } else {
      roots.push(tn)
    }
  }

  // Attach assets under their node
  for (const a of props.assets) {
    const assetLeaf: TreeNodeData = {
      key: `asset-${a.id}`,
      label: a.name,
      type: 'asset',
      rawData: a,
    }
    if (a.node_id != null && nodeMap.has(a.node_id)) {
      nodeMap.get(a.node_id)!.children!.push(assetLeaf)
    } else {
      // Orphan asset — put under root
      roots.push(assetLeaf)
    }
  }

  // Remove empty children arrays
  function clean(node: TreeNodeData) {
    if (node.children && node.children.length === 0) {
      delete node.children
    } else if (node.children) {
      node.children.forEach(clean)
    }
  }
  roots.forEach(clean)

  return roots
})

function onNodeClick(data: TreeNodeData) {
  emit('node-click', { type: data.type, data: data.rawData })
}
</script>

<style scoped>
.tree-node {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.tree-node.is-asset {
  color: #409eff;
}

.node-icon {
  color: #e6a23c;
}

.asset-icon {
  color: #409eff;
}
</style>
