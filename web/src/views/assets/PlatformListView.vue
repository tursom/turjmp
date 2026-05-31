<template>
  <div class="page-container">
    <div class="page-header">
      <h2>Platforms</h2>
      <el-button v-if="canCreatePlatform" type="primary" @click="openCreate">
        New Platform
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="platforms"
      stripe
      border
      empty-text="No platforms found"
    >
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="name" label="Name" min-width="160" />
      <el-table-column prop="type" label="Type" width="140" />
      <el-table-column prop="description" label="Description" min-width="240" />
    </el-table>

    <el-empty v-if="!loading && platforms.length === 0" description="No platforms available" />

    <el-dialog v-model="dialogVisible" title="New Platform Template" width="520px" @close="resetForm">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
        <el-form-item label="Name" prop="name">
          <el-input v-model="form.name" placeholder="Linux, Windows, MySQL..." />
        </el-form-item>
        <el-form-item label="Type" prop="type">
          <el-input v-model="form.type" placeholder="linux, windows, mysql..." />
        </el-form-item>
        <el-form-item label="Protocol">
          <el-input v-model="form.protocol" placeholder="ssh, rdp, mysql..." />
        </el-form-item>
        <el-form-item label="Port">
          <el-input-number v-model="form.port" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>
        <el-form-item label="Description">
          <el-input v-model="form.description" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">Cancel</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreate">
          Create
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import * as assetsApi from '@/api/assets'
import { useAuthStore } from '@/stores/auth'
import type { Platform } from '@/types'

const authStore = useAuthStore()
const loading = ref(false)
const platforms = ref<Platform[]>([])
const dialogVisible = ref(false)
const creating = ref(false)
const formRef = ref<FormInstance>()

const form = reactive({
  name: '',
  type: '',
  protocol: '',
  port: 22,
  description: '',
})

const rules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  type: [{ required: true, message: 'Type is required', trigger: 'blur' }],
}

const canCreatePlatform = computed(() => authStore.canAccess('platform_create'))

async function fetchPlatforms() {
  loading.value = true
  try {
    platforms.value = await assetsApi.listPlatforms()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load platforms')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  dialogVisible.value = true
}

function resetForm() {
  form.name = ''
  form.type = ''
  form.protocol = ''
  form.port = 22
  form.description = ''
  formRef.value?.resetFields()
}

async function handleCreate() {
  if (!formRef.value) return
  try {
    await formRef.value.validate()
  } catch {
    return
  }
  creating.value = true
  try {
    const platform = await assetsApi.createPlatform({
      name: form.name,
      type: form.type,
      protocol: form.protocol || undefined,
      port: form.protocol ? form.port : undefined,
      description: form.description || undefined,
    })
    ElMessage.success(`Platform "${platform.name}" saved`)
    dialogVisible.value = false
    resetForm()
    await fetchPlatforms()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to create platform')
  } finally {
    creating.value = false
  }
}

onMounted(() => {
  fetchPlatforms()
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
}
</style>
