<template>
  <div class="page-container">
    <div class="page-header">
      <h2>{{ isEdit ? 'Edit Asset' : 'New Asset' }}</h2>
    </div>

    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-width="140px"
      class="asset-form"
    >
      <el-form-item label="Name" prop="name">
        <el-input v-model="form.name" placeholder="Asset name" maxlength="128" />
      </el-form-item>

      <el-form-item label="Address" prop="address">
        <el-input v-model="form.address" placeholder="IP or hostname" maxlength="256" />
      </el-form-item>

      <el-form-item label="Platform" prop="platform_id">
        <el-select
          v-model="form.platform_id"
          placeholder="Select platform"
          class="full-width"
        >
          <el-option
            v-for="p in platforms"
            :key="p.id"
            :label="`${p.name} (${p.type})`"
            :value="p.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="Node">
        <el-tree-select
          v-model="form.node_id"
          :data="treeNodes"
          :props="{ label: 'label', children: 'children' }"
          placeholder="Select node (optional)"
          check-strictly
          clearable
          class="full-width"
        />
      </el-form-item>

      <el-form-item label="Comment">
        <el-input
          v-model="form.comment"
          type="textarea"
          :rows="3"
          placeholder="Optional comment"
          maxlength="512"
        />
      </el-form-item>

      <el-form-item label="Active">
        <el-switch v-model="form.is_active" />
      </el-form-item>

      <el-form-item>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">
          {{ isEdit ? 'Update' : 'Create' }}
        </el-button>
        <el-button @click="handleCancel">Cancel</el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import * as assetsApi from '@/api/assets'
import type { Platform, Node } from '@/types'

const route = useRoute()
const router = useRouter()

const isEdit = computed(() => route.name === 'AssetEdit')
const assetId = computed(() => {
  const id = route.params.id
  if (typeof id === 'string') return Number(id)
  return undefined
})

const formRef = ref<FormInstance>()
const submitting = ref(false)
const loading = ref(false)
const platforms = ref<Platform[]>([])
const allNodes = ref<Node[]>([])

interface FormData {
  name: string
  address: string
  platform_id: number | null
  node_id: number | null
  comment: string
  is_active: boolean
}

const form = reactive<FormData>({
  name: '',
  address: '',
  platform_id: null,
  node_id: null,
  comment: '',
  is_active: true,
})

const rules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  address: [{ required: true, message: 'Address is required', trigger: 'blur' }],
  platform_id: [{ required: true, message: 'Platform is required', trigger: 'change' }],
}

interface TreeNode {
  value: number
  label: string
  children?: TreeNode[]
}

function buildTree(nodes: Node[]): TreeNode[] {
  const map = new Map<number, TreeNode>()
  const roots: TreeNode[] = []

  for (const n of nodes) {
    map.set(n.id, { value: n.id, label: n.name, children: [] })
  }
  for (const n of nodes) {
    const node = map.get(n.id)!
    if (n.parent_id != null && map.has(n.parent_id)) {
      map.get(n.parent_id)!.children!.push(node)
    } else {
      roots.push(node)
    }
  }

  // Remove empty children arrays to keep tree clean
  function clean(node: TreeNode) {
    if (node.children && node.children.length === 0) {
      delete node.children
    } else if (node.children) {
      node.children.forEach(clean)
    }
  }
  roots.forEach(clean)

  return roots
}

const treeNodes = computed(() => buildTree(allNodes.value))

async function loadOptions() {
  loading.value = true
  try {
    const [platData, treeData] = await Promise.all([
      assetsApi.listPlatforms(),
      assetsApi.getTree(),
    ])
    platforms.value = platData
    allNodes.value = treeData.nodes
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load data')
  } finally {
    loading.value = false
  }
}

async function loadAsset() {
  if (!isEdit.value || assetId.value == null) return
  try {
    const asset = await assetsApi.get(assetId.value)
    form.name = asset.name
    form.address = asset.address
    form.platform_id = asset.platform_id
    form.node_id = asset.node_id ?? null
    form.comment = asset.comment ?? ''
    form.is_active = asset.is_active
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load asset')
    router.push('/assets')
  }
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    const payload = {
      name: form.name,
      address: form.address,
      platform_id: form.platform_id as number,
      node_id: form.node_id ?? undefined,
      comment: form.comment || undefined,
      is_active: form.is_active,
    }

    if (isEdit.value && assetId.value != null) {
      await assetsApi.update(assetId.value, payload)
      ElMessage.success('Asset updated')
    } else {
      await assetsApi.create(payload)
      ElMessage.success('Asset created')
    }
    router.push('/assets')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Save failed')
  } finally {
    submitting.value = false
  }
}

function handleCancel() {
  router.push('/assets')
}

onMounted(() => {
  loadOptions().then(() => {
    if (isEdit.value) {
      loadAsset()
    }
  })
})
</script>

<style scoped>
.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}

.asset-form {
  max-width: 640px;
}

.full-width {
  width: 100%;
}
</style>
