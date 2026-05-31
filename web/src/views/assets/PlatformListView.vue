<template>
  <div class="page-container">
    <div class="page-header">
      <h2>平台模板</h2>
      <el-button v-if="canCreatePlatform" type="primary" @click="openCreate">
        新建平台
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="platforms"
      stripe
      border
      empty-text="未找到平台模板"
    >
      <el-table-column prop="id" label="ID" width="80" />
      <el-table-column prop="name" label="名称" min-width="160" />
      <el-table-column prop="type" label="类型" width="140" />
      <el-table-column prop="description" label="描述" min-width="240" />
    </el-table>

    <el-empty v-if="!loading && platforms.length === 0" description="暂无平台模板" />

    <el-dialog v-model="dialogVisible" title="新建平台模板" width="520px" @close="resetForm">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="120px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name"           placeholder="Linux、Windows、MySQL..." />
        </el-form-item>
        <el-form-item label="类型" prop="type">
          <el-input v-model="form.type"           placeholder="linux、windows、mysql..." />
        </el-form-item>
        <el-form-item label="协议">
          <el-input v-model="form.protocol"           placeholder="ssh、rdp、mysql..." />
        </el-form-item>
        <el-form-item label="端口">
          <el-input-number v-model="form.port" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="form.description" type="textarea" :rows="3" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="handleCreate">
          创建
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
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  type: [{ required: true, message: '请输入类型', trigger: 'blur' }],
}

const canCreatePlatform = computed(() => authStore.canAccess('platform_create'))

async function fetchPlatforms() {
  loading.value = true
  try {
    platforms.value = await assetsApi.listPlatforms()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '加载平台模板失败')
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
    ElMessage.success(`平台模板“${platform.name}”已保存`)
    dialogVisible.value = false
    resetForm()
    await fetchPlatforms()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '创建平台模板失败')
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
