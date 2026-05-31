<template>
  <div class="account-management">
    <div class="toolbar">
      <el-button v-if="canCreateAccounts" type="primary" @click="openCreate">
        Add Account
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="accounts"
      stripe
      border
    >
      <el-table-column prop="name" label="Name" min-width="120" />
      <el-table-column prop="username" label="Username" min-width="120" />
      <el-table-column prop="secret_type" label="Secret Type" width="120" />
      <el-table-column label="Status" width="100">
        <template #default="{ row }">
          <el-tag :type="row.is_active ? 'success' : 'info'" size="small">
            {{ row.is_active ? 'Active' : 'Inactive' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="Actions" width="160" fixed="right">
        <template #default="{ row }">
          <el-button v-if="canUpdateAccounts" size="small" type="primary" @click="openEdit(row)">Edit</el-button>
          <el-button
            v-if="canDeleteAccounts"
            size="small"
            type="danger"
            @click="handleDelete(row)"
          >
            Delete
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty
      v-if="!loading && accounts.length === 0"
      description="No accounts yet. Add one to get started."
    />

    <el-dialog
      v-model="dialogVisible"
      :title="isEditing ? 'Edit Account' : 'Add Account'"
      width="560px"
      destroy-on-close
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-width="130px"
      >
        <el-form-item label="Name" prop="name">
          <el-input v-model="form.name" placeholder="Account name" maxlength="128" />
        </el-form-item>

        <el-form-item label="Username" prop="username">
          <el-input v-model="form.username" placeholder="Login username" maxlength="128" />
        </el-form-item>

        <el-form-item label="Secret Type" prop="secret_type">
          <el-select v-model="form.secret_type" class="full-width" @change="onSecretTypeChange">
            <el-option label="Password" value="password" />
            <el-option label="SSH Key" value="ssh_key" />
            <el-option label="Token" value="token" />
          </el-select>
        </el-form-item>

        <el-form-item
          :label="secretLabel"
          :prop="isEditing && !secretModified ? '' : 'secret'"
        >
          <el-input
            v-if="form.secret_type === 'ssh_key'"
            v-model="form.secret"
            type="textarea"
            :rows="4"
            :placeholder="secretPlaceholder"
            @input="onSecretInput"
          />
          <el-input
            v-else
            v-model="form.secret"
            type="password"
            show-password
            :placeholder="secretPlaceholder"
            @input="onSecretInput"
          />
        </el-form-item>

        <el-form-item v-if="form.secret_type === 'ssh_key'" label="SSH Key Type">
          <el-select v-model="form.ssh_key_type" clearable class="full-width">
            <el-option label="RSA" value="rsa" />
            <el-option label="Ed25519" value="ed25519" />
            <el-option label="ECDSA" value="ecdsa" />
          </el-select>
        </el-form-item>

        <el-form-item label="Passphrase">
          <el-input
            v-model="form.passphrase"
            type="password"
            show-password
            placeholder="Optional passphrase"
            maxlength="256"
          />
        </el-form-item>

        <el-form-item label="SU Enabled">
          <el-switch v-model="form.su_enabled" />
        </el-form-item>

        <el-form-item v-if="form.su_enabled" label="SU Method">
          <el-select v-model="form.su_method" class="full-width">
            <el-option label="su" value="su" />
            <el-option label="sudo" value="sudo" />
          </el-select>
        </el-form-item>

        <el-form-item
          v-if="isDatabasePlatform"
          label="Database Name"
        >
          <el-input v-model="form.db_name" placeholder="Database name" maxlength="128" />
        </el-form-item>

        <el-form-item label="Active">
          <el-switch v-model="form.is_active" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">Cancel</el-button>
        <el-button type="primary" :loading="submitting" @click="handleSubmit">
          {{ isEditing ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import * as assetsApi from '@/api/assets'
import { useAuthStore } from '@/stores/auth'
import type { Account, AccountInput } from '@/types'

const props = defineProps<{
  assetId: number
  platformType?: string
}>()

const authStore = useAuthStore()
const loading = ref(false)
const accounts = ref<Account[]>([])
const dialogVisible = ref(false)
const isEditing = ref(false)
const editingAccountId = ref<number | null>(null)
const submitting = ref(false)
const secretModified = ref(false)
const formRef = ref<FormInstance>()

const isDatabasePlatform = computed(() =>
  props.platformType
    ? ['mysql', 'postgres', 'postgresql'].includes(props.platformType.toLowerCase()) ||
      props.platformType.toLowerCase().includes('database')
    : false,
)

const canCreateAccounts = computed(() => authStore.canAccess('account_create'))
const canUpdateAccounts = computed(() => authStore.canAccess('account_update'))
const canDeleteAccounts = computed(() => authStore.canAccess('account_delete'))

const secretLabel = computed(() => {
  if (form.secret_type === 'password') return 'Password'
  if (form.secret_type === 'ssh_key') return 'SSH Private Key'
  return 'Token'
})

const secretPlaceholder = computed(() => {
  if (isEditing.value && !secretModified.value) {
    return 'Leave empty to keep current secret'
  }
  return form.secret_type === 'ssh_key' ? 'Paste private key...' : 'Enter secret'
})

interface FormData {
  name: string
  username: string
  secret_type: 'password' | 'ssh_key' | 'token'
  secret: string
  ssh_key_type?: string
  passphrase: string
  su_enabled: boolean
  su_method?: string
  db_name?: string
  is_active: boolean
}

const form = reactive<FormData>({
  name: '',
  username: '',
  secret_type: 'password',
  secret: '',
  ssh_key_type: undefined,
  passphrase: '',
  su_enabled: false,
  su_method: undefined,
  db_name: undefined,
  is_active: true,
})

const rules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  username: [{ required: true, message: 'Username is required', trigger: 'blur' }],
  secret_type: [{ required: true, message: 'Secret type is required', trigger: 'change' }],
  secret: [{ required: true, message: 'Secret is required', trigger: 'blur' }],
}

function onSecretInput() {
  secretModified.value = true
}

function onSecretTypeChange() {
  form.secret = ''
  form.ssh_key_type = undefined
  secretModified.value = true
}

function resetForm() {
  form.name = ''
  form.username = ''
  form.secret_type = 'password'
  form.secret = ''
  form.ssh_key_type = undefined
  form.passphrase = ''
  form.su_enabled = false
  form.su_method = undefined
  form.db_name = undefined
  form.is_active = true
  secretModified.value = false
  formRef.value?.resetFields()
}

function openCreate() {
  isEditing.value = false
  editingAccountId.value = null
  resetForm()
  dialogVisible.value = true
}

function openEdit(account: Account) {
  isEditing.value = true
  editingAccountId.value = account.id
  form.name = account.name
  form.username = account.username
  form.secret_type = account.secret_type
  form.secret = account.secret || ''
  form.ssh_key_type = account.ssh_key_type
  form.passphrase = account.passphrase || ''
  form.su_enabled = account.su_enabled
  form.su_method = account.su_method
  form.db_name = account.db_name
  form.is_active = account.is_active
  secretModified.value = false
  dialogVisible.value = true
}

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    const secretValue = isEditing.value && !secretModified.value ? '' : form.secret

    const payload: AccountInput = {
      name: form.name,
      username: form.username,
      secret: secretValue,
      secret_type: form.secret_type as AccountInput['secret_type'],
      ssh_key_type: form.ssh_key_type || undefined,
      passphrase: form.passphrase || undefined,
      su_enabled: form.su_enabled,
      su_method: form.su_enabled ? (form.su_method ?? undefined) : undefined,
      db_name: form.db_name || undefined,
      is_active: form.is_active,
    }

    if (isEditing.value && editingAccountId.value != null) {
      await assetsApi.updateAccount(props.assetId, editingAccountId.value, payload)
      ElMessage.success('Account updated')
    } else {
      await assetsApi.createAccount(props.assetId, payload)
      ElMessage.success('Account created')
    }
    dialogVisible.value = false
    await fetchAccounts()
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Save failed')
  } finally {
    submitting.value = false
  }
}

async function handleDelete(account: Account) {
  try {
    await ElMessageBox.confirm(
      `Delete account "${account.name}"? This cannot be undone.`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      },
    )
    await assetsApi.deleteAccount(props.assetId, account.id)
    ElMessage.success('Account deleted')
    accounts.value = accounts.value.filter((a) => a.id !== account.id)
  } catch (err) {
    if (err !== 'cancel' && err !== 'close') {
      ElMessage.error(err instanceof Error ? err.message : 'Delete failed')
    }
  }
}

async function fetchAccounts() {
  loading.value = true
  try {
    accounts.value = await assetsApi.listAccounts(props.assetId)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : 'Failed to load accounts')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchAccounts()
})

// Re-fetch when assetId changes (parent re-mount scenario)
watch(() => props.assetId, () => {
  fetchAccounts()
})
</script>

<style scoped>
.account-management {
  padding-top: 4px;
}

.toolbar {
  margin-bottom: 12px;
}

.full-width {
  width: 100%;
}
</style>
